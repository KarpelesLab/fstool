//! In-memory authoring — create a blank filesystem or a partitioned disk,
//! edit it, and export the bytes at any point.
//!
//! Where [`crate::memconv`] is byte-in / byte-out (probe an existing blob,
//! browse it, transcode it), this module is the *authoring* half: start from
//! nothing, format a volume, add files and directories, and hand back the
//! image whenever the caller asks. It exists for the browser build, where
//! there is no host filesystem to stage into, but nothing here is
//! wasm-specific.
//!
//! Everything hangs off one type, [`Workspace`], which owns the whole image
//! and hands out a checked-out view of one filesystem at a time:
//!
//! ```text
//!   Workspace
//!     disk:  Vec<u8>          the bytes that get downloaded
//!     table: Option<..>       partition layout, for a whole-disk workspace
//!     open:  Option<OpenFs>   the filesystem currently being edited
//! ```
//!
//! A bare-filesystem workspace has no table and its single filesystem spans
//! the whole image. A disk workspace starts as an empty MBR/GPT and grows
//! partitions one at a time; opening partition *N* copies its byte range out
//! into a scratch device, and every edit is spliced back into `disk` on the
//! next [`Workspace::export`] or when a different partition is opened. That
//! keeps the invariant the caller cares about — *the bytes you download are
//! the bytes you edited* — inside Rust rather than in the UI.
//!
//! ```no_run
//! use fstool::memedit::Workspace;
//! let mut ws = Workspace::new_filesystem("ext4", 32 << 20, "")?;
//! ws.mkdir("/etc")?;
//! ws.add_file("/etc/hostname", b"fstool\n".to_vec())?;
//! let image = ws.export()?;          // a real ext4 image
//! # Ok::<(), fstool::Error>(())
//! ```

use serde::Serialize;

use crate::block::{BlockDevice, MemoryBackend};
use crate::format_opts::OptionMap;
use crate::fs::{FileMeta, FileSource, FilesystemFactory, MutationCapability};
use crate::inspect::AnyFs;
use crate::part::{Gpt, Mbr, Partition, PartitionKind, PartitionTable};
use crate::{Error, Result};

/// Sector size every layout calculation here assumes.
const SECTOR: u64 = 512;
/// Partition start alignment, in sectors (1 MiB — what every modern
/// partitioner uses).
const ALIGN_LBA: u64 = 2048;
/// LBAs GPT reserves at the end of the disk for its backup table.
const GPT_TAIL_LBA: u64 = 34;

// ======================================================================
// The catalogue of filesystems a workspace can create.
// ======================================================================

/// A filesystem type [`Workspace::new_filesystem`] can format from scratch.
#[derive(Debug, Clone, Serialize)]
pub struct FsTypeInfo {
    /// Id accepted by [`Workspace::new_filesystem`] and `add_partition`.
    pub id: &'static str,
    /// Human label for a picker.
    pub label: &'static str,
    /// Smallest volume this writer accepts, in bytes. Offering anything
    /// below this just produces a format error.
    pub min_size: u64,
    /// A size that comfortably works, for pre-filling a form.
    pub default_size: u64,
    /// Whether files can be added *after* formatting. `false` marks the
    /// build-once formats (squashfs, ISO, the archive writers), which
    /// still accept content — they just can't be re-opened and extended,
    /// so a workspace keeps their handle alive for the whole session.
    pub editable: bool,
    /// `-O key=val` knobs worth surfacing, comma-separated. Empty when the
    /// defaults are the only sensible choice.
    pub options: &'static str,
}

/// Every filesystem a [`Workspace`] can create. The list is deliberately
/// conservative: each entry is exercised by
/// `every_advertised_filesystem_formats_and_accepts_a_file`, so an id that
/// appears here really does format blank and really does take a file.
pub fn creatable_filesystems() -> Vec<FsTypeInfo> {
    vec![
        FsTypeInfo {
            id: "ext2",
            label: "ext2",
            min_size: 1 << 20,
            default_size: 32 << 20,
            editable: true,
            options: "block_size,volume_label,inodes_count",
        },
        FsTypeInfo {
            id: "ext3",
            label: "ext3 (journalled)",
            min_size: 8 << 20,
            default_size: 64 << 20,
            editable: true,
            options: "block_size,volume_label,journal_blocks",
        },
        FsTypeInfo {
            id: "ext4",
            label: "ext4",
            min_size: 8 << 20,
            default_size: 64 << 20,
            editable: true,
            options: "block_size,volume_label,journal_blocks",
        },
        FsTypeInfo {
            id: "fat12",
            label: "FAT12",
            min_size: 64 << 10,
            default_size: 1440 << 10,
            editable: true,
            options: "volume_label,volume_id,root_entries",
        },
        FsTypeInfo {
            id: "fat16",
            label: "FAT16",
            min_size: 4 << 20,
            default_size: 32 << 20,
            editable: true,
            options: "volume_label,volume_id,root_entries",
        },
        FsTypeInfo {
            id: "fat32",
            label: "FAT32",
            min_size: 34 << 20,
            default_size: 64 << 20,
            editable: true,
            options: "volume_label,volume_id",
        },
        FsTypeInfo {
            id: "exfat",
            label: "exFAT",
            min_size: 16 << 20,
            default_size: 64 << 20,
            editable: true,
            options: "volume_label",
        },
        FsTypeInfo {
            id: "ntfs",
            label: "NTFS",
            min_size: 16 << 20,
            default_size: 64 << 20,
            editable: true,
            options: "volume_label",
        },
        FsTypeInfo {
            id: "xfs",
            label: "XFS",
            min_size: 32 << 20,
            default_size: 128 << 20,
            editable: true,
            options: "",
        },
        FsTypeInfo {
            id: "hfs+",
            label: "HFS+",
            min_size: 4 << 20,
            default_size: 64 << 20,
            editable: true,
            options: "volume_name,journaled",
        },
        FsTypeInfo {
            id: "hfs",
            label: "HFS (Mac OS ≤ 8)",
            min_size: 1 << 20,
            default_size: 32 << 20,
            editable: true,
            options: "volume_name",
        },
        FsTypeInfo {
            id: "affs",
            label: "Amiga OFS/FFS",
            min_size: 512 << 10,
            default_size: 880 << 10,
            editable: true,
            options: "fstype,intl,volume_name",
        },
        FsTypeInfo {
            id: "f2fs",
            label: "F2FS",
            min_size: 64 << 20,
            default_size: 128 << 20,
            editable: true,
            options: "",
        },
        FsTypeInfo {
            id: "grf",
            label: "GRF (Ragnarok)",
            min_size: 64 << 10,
            default_size: 16 << 20,
            editable: true,
            options: "",
        },
    ]
}

/// Look up a creatable filesystem by id.
fn fs_type_info(id: &str) -> Option<&'static FsTypeInfo> {
    // The catalogue is static data; leak it once so callers get a
    // `'static` reference without rebuilding the vec on every lookup.
    use std::sync::OnceLock;
    static ALL: OnceLock<Vec<FsTypeInfo>> = OnceLock::new();
    let all = ALL.get_or_init(creatable_filesystems);
    let id = id.trim().to_ascii_lowercase();
    all.iter().find(|f| f.id == id)
}

/// Normalise the aliases a user might type for a filesystem id.
fn canonical_fs_id(fs_type: &str) -> String {
    match fs_type.trim().to_ascii_lowercase().as_str() {
        "vfat" => "fat32".to_string(),
        "hfsplus" => "hfs+".to_string(),
        "ofs" | "ffs" => "affs".to_string(),
        other => other.to_string(),
    }
}

// ======================================================================
// Formatting a blank filesystem.
// ======================================================================

/// Format a blank filesystem of `fs_type` onto `dev`, which must already be
/// sized. `options` is a `-O`-style `key=val,key=val` string.
///
/// Returns the *live* handle, not a re-opened one. That matters for the
/// build-once writers (F2FS most obviously): a freshly formatted handle
/// accepts content, a re-opened one does not.
fn format_blank(fs_type: &str, dev: &mut MemoryBackend, options: &str) -> Result<AnyFs> {
    let id = canonical_fs_id(fs_type);
    let mut bag = if options.trim().is_empty() {
        OptionMap::new()
    } else {
        OptionMap::from_cli(options)?
    };
    let size = dev.total_size();

    let fs = match id.as_str() {
        "ext2" | "ext3" | "ext4" => {
            use crate::fs::ext::{Ext, FormatOpts, FsKind};
            let kind = match id.as_str() {
                "ext2" => FsKind::Ext2,
                "ext3" => FsKind::Ext3,
                _ => FsKind::Ext4,
            };
            // `block_size` has to be settled before the rest of the layout,
            // so it comes off the bag first (as the CLI's `create` does).
            let block_size = bag.take_u32("block_size")?.unwrap_or(4096);
            let mut opts = FormatOpts {
                kind,
                block_size,
                // A fresh MemoryBackend is already zero, so the formatter
                // can skip its up-front zeroing pass.
                prezeroed: true,
                sparse: true,
                ..FormatOpts::default()
            };
            // Fill the device: blocks stay a multiple of 8 for the bitmap,
            // and inode density tracks mke2fs's 1-per-16-KiB rule.
            let max_blocks = u32::try_from(size / u64::from(block_size)).unwrap_or(u32::MAX);
            opts.blocks_count = (max_blocks / 8) * 8;
            opts.inodes_count =
                (u64::from(opts.blocks_count) * u64::from(block_size) / 16_384).max(16) as u32;
            opts.apply_options(&mut bag)?;
            bag.check_empty(&id)?;
            AnyFs::Ext(Box::new(Ext::format_with(dev, &opts)?))
        }
        "fat12" | "fat16" | "fat32" => {
            use crate::fs::fat::{Fat32, FatFormatOpts, parse_fat_kind};
            let total_sectors = u32::try_from(size / SECTOR).map_err(|_| {
                Error::InvalidArgument("fat: volume too large for a 32-bit sector count".into())
            })?;
            let mut opts = FatFormatOpts {
                kind: parse_fat_kind(&id)?,
                total_sectors,
                ..FatFormatOpts::default()
            };
            opts.apply_options(&mut bag)?;
            opts.total_sectors = total_sectors;
            bag.check_empty(&id)?;
            AnyFs::Fat32(Box::new(Fat32::format(dev, &opts)?))
        }
        "exfat" => {
            use crate::fs::exfat::{Exfat, FormatOpts};
            let mut opts = FormatOpts::default();
            opts.apply_options(&mut bag)?;
            bag.check_empty(&id)?;
            AnyFs::Exfat(Box::new(Exfat::format(dev, &opts)?))
        }
        "ntfs" => {
            use crate::fs::ntfs::{Ntfs, format::FormatOpts};
            let mut opts = FormatOpts::default();
            opts.apply_options(&mut bag)?;
            bag.check_empty(&id)?;
            AnyFs::Ntfs(Box::new(Ntfs::format(dev, &opts)?))
        }
        "xfs" => {
            use crate::fs::xfs::{Xfs, format::FormatOpts};
            let mut opts = FormatOpts::default();
            opts.apply_options(&mut bag)?;
            bag.check_empty(&id)?;
            AnyFs::Xfs(Box::new(Xfs::format(dev, &opts)?))
        }
        "hfs+" => {
            use crate::fs::hfs_plus::{FormatOpts, HfsPlus};
            let mut opts = FormatOpts {
                volume_name: "Untitled".to_string(),
                ..FormatOpts::default()
            };
            opts.apply_options(&mut bag)?;
            bag.check_empty(&id)?;
            AnyFs::HfsPlus(Box::new(HfsPlus::format(dev, &opts)?))
        }
        "hfs" => {
            use crate::fs::hfs::{Hfs, HfsFormatOpts};
            // Classic HFS has no `apply_options`; its two knobs are read
            // straight off the bag, matching `spec::hfs_format_opts`.
            let mut opts = HfsFormatOpts::default();
            if let Some(name) = bag
                .take_str("volume_name")
                .or_else(|| bag.take_str("volume_label"))
            {
                opts.volume_name = name;
            }
            if let Some(b) = bag.take_u32("block_size")? {
                opts.block_size = Some(b);
            }
            bag.check_empty(&id)?;
            AnyFs::Hfs(Box::new(Hfs::format(dev, &opts)?))
        }
        "affs" => {
            use crate::fs::affs::{Affs, AffsFormatOpts};
            // Same knobs `spec::affs_format_opts` accepts.
            let mut opts = AffsFormatOpts::default();
            if let Some(name) = bag
                .take_str("volume_name")
                .or_else(|| bag.take_str("volume_label"))
            {
                opts.volume_name = name;
            }
            if let Some(t) = bag.take_str("fstype") {
                match t.to_ascii_lowercase().as_str() {
                    "ffs" => opts.ffs = true,
                    "ofs" => opts.ffs = false,
                    other => {
                        return Err(Error::InvalidArgument(format!(
                            "affs: unknown fstype {other:?} (use ffs|ofs)"
                        )));
                    }
                }
            }
            if let Some(b) = bag.take_bool("intl")? {
                opts.intl = b;
            }
            bag.check_empty(&id)?;
            AnyFs::Affs(Box::new(Affs::format(dev, &opts)?))
        }
        "f2fs" => {
            use crate::fs::f2fs::{F2fs, FormatOpts};
            let opts = FormatOpts::default();
            bag.check_empty(&id)?;
            AnyFs::F2fs(Box::new(F2fs::format(dev, &opts)?))
        }
        "grf" => {
            use crate::fs::grf::{FormatOpts, Grf};
            let mut opts = FormatOpts::default();
            opts.apply_options(&mut bag)?;
            bag.check_empty(&id)?;
            AnyFs::Grf(Box::new(Grf::format(dev, &opts)?))
        }
        other => {
            return Err(Error::InvalidArgument(format!(
                "cannot create a blank {other:?} filesystem — see \
                 memedit::creatable_filesystems()"
            )));
        }
    };
    Ok(fs)
}

// ======================================================================
// Workspace.
// ======================================================================

/// A filesystem checked out of the workspace for editing.
struct OpenFs {
    /// 1-indexed partition this came from; `None` for a bare-FS workspace.
    partition: Option<usize>,
    /// Byte range within `Workspace::disk` that this filesystem occupies.
    start: u64,
    len: u64,
    dev: MemoryBackend,
    fs: AnyFs,
}

/// Description of a workspace, for a UI to render. Serializable.
#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceInfo {
    /// `"gpt"` / `"mbr"` for a disk workspace, `None` for a bare filesystem.
    pub table: Option<String>,
    /// Total image size in bytes — what `export` will hand back.
    pub size: u64,
    /// Partitions, empty for a bare-filesystem workspace.
    pub partitions: Vec<PartitionInfo>,
    /// The partition currently open for editing, if any.
    pub open_partition: Option<usize>,
    /// Filesystem kind currently open for editing, if any.
    pub open_fs: Option<String>,
    /// Whether the open filesystem accepts `add_file` / `mkdir` / `remove`.
    pub open_editable: bool,
    /// Free bytes not yet covered by a partition (disk workspaces only).
    pub free_bytes: u64,
}

/// One partition of a disk workspace.
#[derive(Debug, Clone, Serialize)]
pub struct PartitionInfo {
    /// 1-indexed, matching `disk.img:N`.
    pub index: usize,
    pub name: Option<String>,
    /// Semantic kind (`"linux"`, `"esp"`, `"fat32"`, …).
    pub kind: String,
    pub start: u64,
    pub size: u64,
    /// Filesystem formatted into it, if any.
    pub fs: Option<String>,
}

/// An in-memory image being authored: a bare filesystem or a partitioned
/// disk. See the [module docs](self) for the model.
///
/// The `Debug` impl deliberately omits `disk` — it is the whole image.
pub struct Workspace {
    /// The bytes `export` hands back.
    disk: Vec<u8>,
    /// `"gpt"` / `"mbr"`, and the partitions placed so far. `None` for a
    /// bare-filesystem workspace.
    table: Option<(String, Vec<Partition>)>,
    /// Per-partition filesystem id, parallel to the partition list. An
    /// entry is `None` until that partition is formatted.
    part_fs: Vec<Option<String>>,
    open: Option<OpenFs>,
}

impl std::fmt::Debug for Workspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Workspace")
            .field("size", &self.disk.len())
            .field("table", &self.table.as_ref().map(|(l, p)| (l, p.len())))
            .field(
                "open_partition",
                &self.open.as_ref().and_then(|o| o.partition),
            )
            .finish()
    }
}

impl Workspace {
    // -- construction ---------------------------------------------------

    /// Format a blank `fs_type` filesystem of `size` bytes and open it for
    /// editing. `options` is a `-O`-style `key=val,key=val` string.
    pub fn new_filesystem(fs_type: &str, size: u64, options: &str) -> Result<Self> {
        let id = canonical_fs_id(fs_type);
        if let Some(info) = fs_type_info(&id)
            && size < info.min_size
        {
            return Err(Error::InvalidArgument(format!(
                "{}: needs at least {} bytes, got {size}",
                info.label, info.min_size
            )));
        }
        let mut dev = MemoryBackend::new(size);
        let fs = format_blank(&id, &mut dev, options)?;
        let disk = vec![0u8; size as usize];
        let mut ws = Self {
            disk,
            table: None,
            part_fs: Vec::new(),
            open: Some(OpenFs {
                partition: None,
                start: 0,
                len: size,
                dev,
                fs,
            }),
        };
        // Land the freshly formatted bytes in `disk` straight away, so an
        // export before any edit still produces a valid image.
        ws.sync_open()?;
        Ok(ws)
    }

    /// Create a blank whole-disk image of `size` bytes carrying an empty
    /// `table` (`"gpt"` or `"mbr"`). Add partitions with
    /// [`add_partition`](Self::add_partition).
    pub fn new_disk(size: u64, table: &str) -> Result<Self> {
        let label = table.trim().to_ascii_lowercase();
        if label != "gpt" && label != "mbr" {
            return Err(Error::InvalidArgument(format!(
                "unknown partition table {table:?} (want gpt or mbr)"
            )));
        }
        let min = (ALIGN_LBA + GPT_TAIL_LBA + ALIGN_LBA) * SECTOR;
        if size < min {
            return Err(Error::InvalidArgument(format!(
                "a partitioned disk needs at least {min} bytes, got {size}"
            )));
        }
        let mut ws = Self {
            disk: vec![0u8; size as usize],
            table: Some((label, Vec::new())),
            part_fs: Vec::new(),
            open: None,
        };
        ws.write_table()?;
        Ok(ws)
    }

    /// Adopt an existing image for editing. A partitioned disk keeps its
    /// table and partitions; a bare filesystem is opened directly.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let mut probe = MemoryBackend::from_bytes(bytes);
        if let Some(detected) = crate::inspect::detect_partition_table(&mut probe)? {
            let label = detected.label().to_string();
            let parts = detected.partitions().to_vec();
            let disk = probe.into_bytes();
            let part_fs = vec![None; parts.len()];
            let mut ws = Self {
                disk,
                table: Some((label, parts)),
                part_fs,
                open: None,
            };
            // Probe each partition so the UI can show what's in it.
            for i in 1..=ws.partitions().len() {
                ws.part_fs[i - 1] = ws.probe_partition(i);
            }
            return Ok(ws);
        }
        let disk = probe.into_bytes();
        let len = disk.len() as u64;
        let mut dev = MemoryBackend::from_bytes(disk.clone());
        let fs = AnyFs::open_writable(&mut dev).or_else(|_| AnyFs::open(&mut dev))?;
        Ok(Self {
            disk,
            table: None,
            part_fs: Vec::new(),
            open: Some(OpenFs {
                partition: None,
                start: 0,
                len,
                dev,
                fs,
            }),
        })
    }

    // -- partitions -----------------------------------------------------

    fn partitions(&self) -> &[Partition] {
        self.table
            .as_ref()
            .map(|(_, p)| p.as_slice())
            .unwrap_or(&[])
    }

    /// First LBA a new partition may start at, and the last usable LBA.
    fn free_span(&self) -> (u64, u64) {
        let total_lba = self.disk.len() as u64 / SECTOR;
        let label = self.table.as_ref().map(|(l, _)| l.as_str()).unwrap_or("");
        let last_usable = if label == "gpt" {
            total_lba.saturating_sub(GPT_TAIL_LBA)
        } else {
            total_lba.saturating_sub(1)
        };
        let cursor = self
            .partitions()
            .iter()
            .map(|p| p.start_lba + p.size_lba)
            .max()
            .unwrap_or(ALIGN_LBA);
        (cursor.div_ceil(ALIGN_LBA) * ALIGN_LBA, last_usable)
    }

    /// Append a partition and, when `fs_type` is non-empty, format it.
    ///
    /// `size` is in bytes; `None` claims all remaining space. `kind` is a
    /// partition-type name (`"linux"`, `"esp"`, `"fat32"`, `"msdata"`, a
    /// raw `"0x83"`, or a GPT type UUID). Returns the new 1-indexed
    /// partition number.
    pub fn add_partition(
        &mut self,
        size: Option<u64>,
        kind: &str,
        name: Option<&str>,
        fs_type: &str,
        fs_options: &str,
    ) -> Result<usize> {
        self.sync_open()?;
        let Some((label, _)) = self.table.clone() else {
            return Err(Error::InvalidArgument(
                "this workspace is a bare filesystem, not a partitioned disk".into(),
            ));
        };
        if label == "mbr" && self.partitions().len() >= 4 {
            return Err(Error::InvalidArgument(
                "MBR holds at most 4 partitions — use a GPT disk".into(),
            ));
        }
        let (start, last_usable) = self.free_span();
        if start > last_usable {
            return Err(Error::InvalidArgument(
                "no free space left on the disk".into(),
            ));
        }
        let size_lba = match size {
            Some(bytes) => {
                let n = bytes / SECTOR;
                if n == 0 {
                    return Err(Error::InvalidArgument("partition size is zero".into()));
                }
                n
            }
            None => last_usable + 1 - start,
        };
        if start + size_lba - 1 > last_usable {
            return Err(Error::InvalidArgument(format!(
                "partition of {} bytes does not fit in the {} bytes left",
                size_lba * SECTOR,
                (last_usable + 1 - start) * SECTOR
            )));
        }
        let pkind = crate::spec::parse_partition_kind(kind)?;
        let mut part = Partition::new(start, size_lba, pkind);
        part.name = name.filter(|n| !n.is_empty()).map(|n| n.to_string());

        // Stage the partition, write the table, then format into it. If
        // formatting fails the partition is rolled back so the workspace
        // never holds a half-made entry.
        self.table.as_mut().expect("checked above").1.push(part);
        self.part_fs.push(None);
        let index = self.partitions().len();
        if let Err(e) = self.write_table() {
            self.rollback_partition();
            return Err(e);
        }
        if !fs_type.trim().is_empty()
            && let Err(e) = self.format_partition(index, fs_type, fs_options)
        {
            self.rollback_partition();
            // Rewriting the table can only fail for reasons that would
            // already have failed above; surface the format error.
            let _ = self.write_table();
            return Err(e);
        }
        Ok(index)
    }

    fn rollback_partition(&mut self) {
        if let Some((_, parts)) = self.table.as_mut() {
            parts.pop();
        }
        self.part_fs.pop();
    }

    /// Format partition `index` (1-based) with a blank `fs_type` and leave
    /// it open for editing.
    pub fn format_partition(
        &mut self,
        index: usize,
        fs_type: &str,
        fs_options: &str,
    ) -> Result<()> {
        self.sync_open()?;
        let (start, len) = self.partition_range(index)?;
        let mut dev = MemoryBackend::new(len);
        let fs = format_blank(fs_type, &mut dev, fs_options)?;
        let kind = fs.kind_string().to_string();
        self.open = Some(OpenFs {
            partition: Some(index),
            start,
            len,
            dev,
            fs,
        });
        self.part_fs[index - 1] = Some(kind);
        self.sync_open()
    }

    /// Byte range of partition `index` (1-based) within the disk.
    fn partition_range(&self, index: usize) -> Result<(u64, u64)> {
        let parts = self.partitions();
        let p = parts
            .get(index.wrapping_sub(1))
            .ok_or_else(|| Error::InvalidArgument(format!("no partition {index}")))?;
        let start = p.start_lba * SECTOR;
        let len = p.size_lba * SECTOR;
        let end = start.saturating_add(len);
        if end > self.disk.len() as u64 {
            return Err(Error::InvalidImage(format!(
                "partition {index} runs past the end of the disk"
            )));
        }
        Ok((start, len))
    }

    /// Write (or rewrite) the partition table into `disk`.
    fn write_table(&mut self) -> Result<()> {
        let Some((label, parts)) = self.table.clone() else {
            return Ok(());
        };
        let mut dev = MemoryBackend::from_bytes(std::mem::take(&mut self.disk));
        let res = match label.as_str() {
            "gpt" => Gpt::build(parts).and_then(|t| t.write(&mut dev)),
            "mbr" => Mbr::new(parts).and_then(|t| t.write(&mut dev)),
            other => Err(Error::InvalidArgument(format!(
                "unknown partition table {other:?}"
            ))),
        };
        self.disk = dev.into_bytes();
        res
    }

    /// Best-effort probe of what filesystem partition `index` carries.
    fn probe_partition(&mut self, index: usize) -> Option<String> {
        let (start, len) = self.partition_range(index).ok()?;
        let slice = self.disk.get(start as usize..(start + len) as usize)?;
        let mut dev = MemoryBackend::from_bytes(slice.to_vec());
        crate::inspect::detect_fs(&mut dev)
            .ok()
            .map(|k| format!("{k:?}").to_ascii_lowercase())
    }

    // -- opening / syncing ----------------------------------------------

    /// Check out partition `index` (1-based) for editing. Any pending edits
    /// to the previously-open filesystem are flushed back into the disk
    /// first.
    pub fn open_partition(&mut self, index: usize) -> Result<()> {
        if self.open.as_ref().and_then(|o| o.partition) == Some(index) {
            return Ok(());
        }
        self.sync_open()?;
        let (start, len) = self.partition_range(index)?;
        let slice = self.disk[start as usize..(start + len) as usize].to_vec();
        let mut dev = MemoryBackend::from_bytes(slice);
        let fs = AnyFs::open_writable(&mut dev).or_else(|_| AnyFs::open(&mut dev))?;
        self.part_fs[index - 1] = Some(fs.kind_string().to_string());
        self.open = Some(OpenFs {
            partition: Some(index),
            start,
            len,
            dev,
            fs,
        });
        Ok(())
    }

    /// Flush the open filesystem and splice its bytes back into the disk.
    fn sync_open(&mut self) -> Result<()> {
        let Some(open) = self.open.as_mut() else {
            return Ok(());
        };
        open.fs.flush(&mut open.dev)?;
        let bytes = open.dev.as_slice();
        let start = open.start as usize;
        // A growable device (the archive writers) can end up longer than
        // the slot it was checked out of; keep what fits and report the
        // overflow rather than silently truncating a partition's contents.
        let want = bytes.len().min(open.len as usize);
        if bytes.len() > open.len as usize {
            return Err(Error::Unsupported(format!(
                "the filesystem grew to {} bytes, past the {} bytes it was given",
                bytes.len(),
                open.len
            )));
        }
        if start + want > self.disk.len() {
            return Err(Error::InvalidImage(
                "open filesystem runs past the end of the image".into(),
            ));
        }
        self.disk[start..start + want].copy_from_slice(&bytes[..want]);
        Ok(())
    }

    fn open_mut(&mut self) -> Result<&mut OpenFs> {
        self.open.as_mut().ok_or_else(|| {
            Error::InvalidArgument(
                "no filesystem is open — format a partition or open one first".into(),
            )
        })
    }

    // -- browsing + editing ---------------------------------------------

    /// List a directory of the open filesystem.
    pub fn list(&mut self, path: &str) -> Result<Vec<crate::memconv::EntryInfo>> {
        let open = self.open_mut()?;
        let entries = open.fs.list(&mut open.dev, path)?;
        Ok(entries
            .into_iter()
            .map(|e| crate::memconv::EntryInfo {
                name: e.name,
                kind: crate::memconv::entry_kind_str(e.kind).to_string(),
                size: e.size,
            })
            .collect())
    }

    /// Read a whole file out of the open filesystem.
    ///
    /// Flushes first: several writers stage directory entries in memory and
    /// only serialise them on flush (FAT batches a parent's children), and
    /// the read paths go straight to the device. Without this, a file added
    /// a moment ago reads back as "no such entry".
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>> {
        let open = self.open_mut()?;
        open.fs.flush(&mut open.dev)?;
        let mut out = Vec::new();
        open.fs.copy_file_to(&mut open.dev, path, &mut out)?;
        Ok(out)
    }

    /// Create (or replace) a regular file holding `bytes`.
    ///
    /// Replacing goes through remove-then-create so it works on every
    /// backend, including the ones with no partial-write path.
    pub fn add_file(&mut self, path: &str, bytes: Vec<u8>) -> Result<()> {
        self.write_file(path, bytes, 0o644)
    }

    /// Like [`add_file`](Self::add_file) with an explicit Unix mode.
    pub fn write_file(&mut self, path: &str, bytes: Vec<u8>, mode: u16) -> Result<()> {
        let open = self.open_mut()?;
        // Replace an existing entry rather than erroring; the UI's "upload"
        // and "save edits" are the same operation.
        let existed = open
            .fs
            .getattr(&mut open.dev, std::path::Path::new(path))
            .is_ok();
        if existed {
            open.fs.remove(&mut open.dev, path)?;
        }
        let len = bytes.len() as u64;
        let src = FileSource::Reader {
            reader: Box::new(std::io::Cursor::new(bytes)),
            len,
        };
        let meta = FileMeta {
            mode,
            ..FileMeta::default()
        };
        let dest = std::path::Path::new(path);
        let dev = &mut open.dev;
        open.fs
            .as_filesystem_dyn(move |fs| fs.create_file(dev, dest, src, meta))
    }

    /// Create a directory. Parent directories must already exist.
    pub fn mkdir(&mut self, path: &str) -> Result<()> {
        let open = self.open_mut()?;
        open.fs.mkdir(&mut open.dev, path)
    }

    /// Remove a file, symlink, device node, or empty directory.
    pub fn remove(&mut self, path: &str) -> Result<()> {
        let open = self.open_mut()?;
        open.fs.remove(&mut open.dev, path)
    }

    /// Whether the open filesystem accepts edits.
    pub fn editable(&self) -> bool {
        self.open
            .as_ref()
            .is_some_and(|o| o.fs.mutation_capability() != MutationCapability::Immutable)
    }

    // -- export ---------------------------------------------------------

    /// Flush every pending edit and return the whole image. Cheap to call
    /// repeatedly — the workspace stays usable afterwards.
    pub fn export(&mut self) -> Result<Vec<u8>> {
        self.sync_open()?;
        Ok(self.disk.clone())
    }

    /// A description of the workspace for a UI to render.
    pub fn info(&mut self) -> Result<WorkspaceInfo> {
        self.sync_open()?;
        let (label, parts) = match &self.table {
            Some((l, p)) => (Some(l.clone()), p.clone()),
            None => (None, Vec::new()),
        };
        let partitions = parts
            .iter()
            .enumerate()
            .map(|(i, p)| PartitionInfo {
                index: i + 1,
                name: p.name.clone(),
                kind: partition_kind_name(&p.kind),
                start: p.start_lba * SECTOR,
                size: p.size_lba * SECTOR,
                fs: self.part_fs.get(i).cloned().flatten(),
            })
            .collect();
        let free_bytes = if self.table.is_some() {
            let (start, last_usable) = self.free_span();
            last_usable.saturating_add(1).saturating_sub(start) * SECTOR
        } else {
            0
        };
        Ok(WorkspaceInfo {
            table: label,
            size: self.disk.len() as u64,
            partitions,
            open_partition: self.open.as_ref().and_then(|o| o.partition),
            open_fs: self.open.as_ref().map(|o| o.fs.kind_string().to_string()),
            open_editable: self.editable(),
            free_bytes,
        })
    }
}

/// Short name for a partition kind, matching what `probe` reports.
fn partition_kind_name(kind: &PartitionKind) -> String {
    match kind {
        PartitionKind::Mbr(b) => format!("0x{b:02x}"),
        PartitionKind::Gpt(u) => u.to_string(),
        PartitionKind::Apm(s) => s.clone(),
        other => format!("{other:?}").to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every id the catalogue advertises must actually format blank at its
    /// default size and take a file. This is what keeps
    /// `creatable_filesystems()` honest — an entry that stops working here
    /// is an entry the UI would offer and then fail on.
    #[test]
    fn every_advertised_filesystem_formats_and_accepts_a_file() {
        for info in creatable_filesystems() {
            let mut ws = Workspace::new_filesystem(info.id, info.default_size, "")
                .unwrap_or_else(|e| panic!("{}: format failed: {e}", info.id));
            ws.add_file("/hello.txt", b"hello\n".to_vec())
                .unwrap_or_else(|e| panic!("{}: add_file failed: {e}", info.id));
            let got = ws
                .read_file("/hello.txt")
                .unwrap_or_else(|e| panic!("{}: read back failed: {e}", info.id));
            assert_eq!(got, b"hello\n", "{}", info.id);
            let image = ws
                .export()
                .unwrap_or_else(|e| panic!("{}: export failed: {e}", info.id));
            assert_eq!(
                image.len() as u64,
                info.default_size,
                "{}: export size",
                info.id
            );
            assert_eq!(
                ws.editable(),
                info.editable,
                "{}: editable flag disagrees with the backend",
                info.id
            );
        }
    }

    /// The exported bytes must re-open as the filesystem we asked for, with
    /// the content we put in — proving the workspace hands back a real
    /// image and not just its own scratch buffer.
    #[test]
    fn exported_filesystem_reopens_with_its_content() {
        let mut ws = Workspace::new_filesystem("ext4", 32 << 20, "volume_label=WEB").unwrap();
        ws.mkdir("/etc").unwrap();
        ws.add_file("/etc/hostname", b"fstool\n".to_vec()).unwrap();
        let image = ws.export().unwrap();

        let mut dev = MemoryBackend::from_bytes(image);
        let mut fs = AnyFs::open(&mut dev).unwrap();
        assert_eq!(fs.kind_string(), "ext4");
        let names: Vec<String> = fs
            .list(&mut dev, "/etc")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"hostname".to_string()), "{names:?}");
        let mut body = Vec::new();
        fs.copy_file_to(&mut dev, "/etc/hostname", &mut body)
            .unwrap();
        assert_eq!(body, b"fstool\n");
    }

    /// Exporting twice with an edit in between must show the edit — the
    /// "download at any point" promise.
    #[test]
    fn export_is_repeatable_and_reflects_later_edits() {
        let mut ws = Workspace::new_filesystem("fat16", 16 << 20, "").unwrap();
        ws.add_file("/first.txt", b"one\n".to_vec()).unwrap();
        let a = ws.export().unwrap();
        ws.add_file("/second.txt", b"two\n".to_vec()).unwrap();
        let b = ws.export().unwrap();
        assert_eq!(a.len(), b.len());
        assert_ne!(a, b, "the second export must contain the new file");

        let mut dev = MemoryBackend::from_bytes(b);
        let mut fs = AnyFs::open(&mut dev).unwrap();
        let names: Vec<String> = fs
            .list(&mut dev, "/")
            .unwrap()
            .into_iter()
            .map(|e| e.name.to_ascii_lowercase())
            .collect();
        assert!(names.contains(&"first.txt".to_string()), "{names:?}");
        assert!(names.contains(&"second.txt".to_string()), "{names:?}");
    }

    /// Removing a file must be visible in the next export.
    #[test]
    fn remove_is_reflected_in_the_export() {
        let mut ws = Workspace::new_filesystem("ext2", 8 << 20, "").unwrap();
        ws.add_file("/gone.txt", b"x".to_vec()).unwrap();
        ws.remove("/gone.txt").unwrap();
        let image = ws.export().unwrap();
        let mut dev = MemoryBackend::from_bytes(image);
        let mut fs = AnyFs::open(&mut dev).unwrap();
        let names: Vec<String> = fs
            .list(&mut dev, "/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(!names.contains(&"gone.txt".to_string()), "{names:?}");
    }

    /// A GPT disk with two formatted partitions: the table must be
    /// detectable, both partitions must carry their filesystem, and edits
    /// made in one must survive opening the other.
    #[test]
    fn gpt_disk_with_two_partitions_round_trips() {
        let mut ws = Workspace::new_disk(256 << 20, "gpt").unwrap();
        let esp = ws
            .add_partition(Some(48 << 20), "esp", Some("EFI"), "fat32", "")
            .unwrap();
        assert_eq!(esp, 1);
        ws.add_file("/EFI.TXT", b"boot\n".to_vec()).unwrap();

        let root = ws
            .add_partition(None, "linux", Some("root"), "ext4", "")
            .unwrap();
        assert_eq!(root, 2);
        ws.mkdir("/etc").unwrap();
        ws.add_file("/etc/fstab", b"# fstab\n".to_vec()).unwrap();

        // Switching back must not have lost the first partition's edit.
        ws.open_partition(1).unwrap();
        assert_eq!(ws.read_file("/EFI.TXT").unwrap(), b"boot\n");

        let image = ws.export().unwrap();
        assert_eq!(image.len(), 256 << 20);

        // The exported disk must probe as a real 2-partition GPT.
        let report = crate::memconv::probe(&image).unwrap();
        let table = report.partition_table.expect("gpt table");
        assert_eq!(table.label, "gpt");
        assert_eq!(table.partitions.len(), 2);
        assert_eq!(table.partitions[0].fs.as_deref(), Some("fat32"));
        assert_eq!(table.partitions[1].fs.as_deref(), Some("ext4"));

        // And each partition's content is readable from the exported bytes.
        let mut p2 = crate::memconv::MemImage::open_partition(image, Some(2)).unwrap();
        assert_eq!(p2.read_file("/etc/fstab").unwrap(), b"# fstab\n");
    }

    /// MBR holds four primaries; the fifth must be refused with a message
    /// that says what to do instead.
    #[test]
    fn mbr_refuses_a_fifth_partition() {
        let mut ws = Workspace::new_disk(64 << 20, "mbr").unwrap();
        for _ in 0..4 {
            ws.add_partition(Some(4 << 20), "linux", None, "", "")
                .unwrap();
        }
        let err = ws
            .add_partition(Some(4 << 20), "linux", None, "", "")
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("at most 4"), "{msg}");
        assert!(msg.contains("GPT"), "{msg}");
    }

    /// A partition that doesn't fit is refused, and the workspace is left
    /// exactly as it was — no half-added entry, table still intact.
    #[test]
    fn an_oversized_partition_leaves_the_workspace_untouched() {
        let mut ws = Workspace::new_disk(64 << 20, "gpt").unwrap();
        ws.add_partition(Some(16 << 20), "linux", None, "", "")
            .unwrap();
        let before = ws.export().unwrap();
        let err = ws
            .add_partition(Some(512 << 20), "linux", None, "", "")
            .unwrap_err();
        assert!(format!("{err}").contains("does not fit"), "{err}");
        assert_eq!(ws.info().unwrap().partitions.len(), 1);
        assert_eq!(ws.export().unwrap(), before);
    }

    /// A format failure inside `add_partition` must roll the partition back
    /// rather than leaving an entry pointing at unformatted space.
    #[test]
    fn a_failed_format_rolls_the_partition_back() {
        let mut ws = Workspace::new_disk(64 << 20, "gpt").unwrap();
        // 4 MiB is far below FAT32's ~34 MiB floor.
        let err = ws
            .add_partition(Some(4 << 20), "fat32", None, "fat32", "")
            .unwrap_err();
        assert!(!format!("{err}").is_empty());
        let info = ws.info().unwrap();
        assert!(
            info.partitions.is_empty(),
            "rolled-back partition still listed: {:?}",
            info.partitions
        );
    }

    /// Adopting an existing image must find its partitions and let us edit
    /// one, with the change visible on re-export.
    #[test]
    fn from_bytes_adopts_a_disk_and_keeps_editing() {
        let mut ws = Workspace::new_disk(128 << 20, "mbr").unwrap();
        ws.add_partition(Some(64 << 20), "linux", None, "ext4", "")
            .unwrap();
        ws.add_file("/original.txt", b"a\n".to_vec()).unwrap();
        let image = ws.export().unwrap();

        let mut reopened = Workspace::from_bytes(image).unwrap();
        let info = reopened.info().unwrap();
        assert_eq!(info.table.as_deref(), Some("mbr"));
        assert_eq!(info.partitions.len(), 1);
        reopened.open_partition(1).unwrap();
        assert_eq!(reopened.read_file("/original.txt").unwrap(), b"a\n");
        reopened.add_file("/added.txt", b"b\n".to_vec()).unwrap();

        let out = reopened.export().unwrap();
        let mut p1 = crate::memconv::MemImage::open_partition(out, Some(1)).unwrap();
        assert_eq!(p1.read_file("/added.txt").unwrap(), b"b\n");
        assert_eq!(p1.read_file("/original.txt").unwrap(), b"a\n");
    }

    /// A bare filesystem below its writer's floor is refused up front with
    /// a message naming the minimum, rather than a format-internal error.
    #[test]
    fn undersized_filesystem_is_refused_with_the_minimum() {
        let err = Workspace::new_filesystem("fat32", 1 << 20, "").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("needs at least"), "{msg}");
    }

    /// Writing the same path twice replaces the file instead of erroring —
    /// the UI's "upload" and "save" are one operation.
    #[test]
    fn writing_a_path_twice_replaces_it() {
        let mut ws = Workspace::new_filesystem("ext4", 16 << 20, "").unwrap();
        ws.add_file("/f.txt", b"first".to_vec()).unwrap();
        ws.add_file("/f.txt", b"second-and-longer".to_vec())
            .unwrap();
        assert_eq!(ws.read_file("/f.txt").unwrap(), b"second-and-longer");
    }
}
