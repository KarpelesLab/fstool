//! FAT filesystem reader / writer — FAT12, FAT16 and FAT32.
//!
//! Produces a FAT image from a host directory tree, and reads or modifies
//! one in place. FAT has no concept of symlinks, device nodes, or Unix
//! ownership/permissions, so those are silently skipped when copying a
//! tree. Long file names use VFAT LFN entries; short 8.3 names are
//! generated where needed.
//!
//! The three flavours differ in exactly two places, both handled here so
//! the rest of the module is width-agnostic:
//!
//! - **FAT entry width** — 12, 16 or 32 bits ([`table::FatKind`]). Which one
//!   a volume uses is a function of its data-cluster count, never of the
//!   `fs_type` string in the boot sector.
//! - **The root directory** — FAT32 stores it as an ordinary cluster chain
//!   starting at `root_cluster`; FAT12/FAT16 store it in a fixed region
//!   between the last FAT and the data area, sized at format time and
//!   unable to grow. `DirLayout` papers over the difference: a directory
//!   is a list of `(device offset, length)` chunks either way, and the
//!   FAT12/16 root is addressed by the cluster number `0` — the same value
//!   those volumes already use in a `..` entry pointing at the root.
//!
//! Reference: the public Microsoft FAT specification.

pub mod boot;
pub mod dir;
pub mod fsinfo;
pub mod handle;
pub mod mutate;
pub mod size_plan;
pub mod table;

pub use size_plan::FatSizePlan;
pub use table::FatKind;

use std::io::Read;
use std::path::Path;

use boot::BootSector;
use fsinfo::FsInfo;
use table::Fat;

use crate::Result;
use crate::block::BlockDevice;
use crate::fs::dir_batch::{DEFAULT_CAPACITY, DirBatch};

/// FAT32 requires at least this many data clusters; fewer makes it a
/// FAT12/FAT16 volume, which fsck.vfat rejects as "not FAT32".
pub const MIN_FAT32_CLUSTERS: u32 = 65525;

/// Logical sector size. FAT supports others; fstool fixes it at 512.
pub const SECTOR: u32 = 512;

/// Directory slots per 512-byte sector — the granularity `root_entries`
/// must be a multiple of, since the fixed root region is sector-aligned.
const ROOT_ENTRIES_PER_SECTOR: u16 = (SECTOR / dir::ENTRY_SIZE as u32) as u16;

/// Root-directory slots for a floppy-sized FAT12/16 volume, matching the
/// mkfs.fat convention for 1.44 MB media.
const FLOPPY_ROOT_ENTRIES: u16 = 224;
/// Root-directory slots for anything larger.
const DEFAULT_ROOT_ENTRIES: u16 = 512;
/// Volumes at or below this many sectors (2.88 MB) are treated as floppies
/// when picking a default root-directory size.
const FLOPPY_MAX_SECTORS: u32 = 5760;

/// Options for [`Fat32::format`].
#[derive(Debug, Clone)]
pub struct FatFormatOpts {
    /// Which FAT flavour to produce. Defaults to [`FatKind::Fat32`], so a
    /// caller that says nothing keeps the historical behaviour.
    pub kind: FatKind,
    /// Total volume size in 512-byte sectors.
    pub total_sectors: u32,
    /// Volume ID (serial number).
    pub volume_id: u32,
    /// Volume label — up to 11 bytes, space-padded.
    pub volume_label: [u8; 11],
    /// Slots in the FAT12/FAT16 fixed root directory. `None` picks a
    /// size-appropriate default (224 for floppy-sized media, 512
    /// otherwise). Ignored on FAT32, whose root grows as a cluster chain.
    pub root_entries: Option<u16>,
}

impl Default for FatFormatOpts {
    fn default() -> Self {
        Self {
            kind: FatKind::Fat32,
            total_sectors: 0,
            volume_id: 0,
            volume_label: *b"NO NAME    ",
            root_entries: None,
        }
    }
}

impl FatFormatOpts {
    /// Pull FAT-specific keys out of an
    /// [`OptionMap`](crate::format_opts::OptionMap) and apply them on
    /// top of `self`. Recognised keys:
    ///
    /// - `fat_type` (`fat12` / `12` / `fat16` / `16` / `fat32` / `32`)
    /// - `total_sectors` (u32) — 512-byte sectors. Usually set from
    ///   the device size by the caller, not by the user.
    /// - `volume_id` (u32, decimal or `0x…`)
    /// - `volume_label` (string, ≤ 11 ASCII bytes, space-padded)
    /// - `root_entries` (u16, FAT12/16 only) — fixed root-directory slots;
    ///   must be a non-zero multiple of 16 so the region stays
    ///   sector-aligned.
    pub fn apply_options(&mut self, map: &mut crate::format_opts::OptionMap) -> crate::Result<()> {
        if let Some(s) = map.take_str("fat_type") {
            self.kind = parse_fat_kind(&s)?;
        }
        if let Some(v) = map.take_u32("total_sectors")? {
            self.total_sectors = v;
        }
        if let Some(v) = map.take_u32("volume_id")? {
            self.volume_id = v;
        }
        if let Some(label) = map.take_label::<11>("volume_label", b' ')? {
            self.volume_label = label;
        }
        if let Some(v) = map.take_u32("root_entries")? {
            let v = u16::try_from(v).map_err(|_| {
                crate::Error::InvalidArgument(format!("fat: root_entries={v} exceeds 65535"))
            })?;
            validate_root_entries(v)?;
            self.root_entries = Some(v);
        }
        Ok(())
    }
}

/// Parse a FAT flavour name as accepted by `-t` and `-O fat_type=`.
pub fn parse_fat_kind(s: &str) -> Result<FatKind> {
    match s.trim().to_ascii_lowercase().as_str() {
        "fat12" | "12" => Ok(FatKind::Fat12),
        "fat16" | "16" => Ok(FatKind::Fat16),
        "fat32" | "32" | "vfat" | "fat" => Ok(FatKind::Fat32),
        other => Err(crate::Error::InvalidArgument(format!(
            "fat: unknown FAT type {other:?} — expected fat12, fat16 or fat32"
        ))),
    }
}

/// A generous byte floor for a volume of FAT flavour `fs_type`, used by the
/// `--shrink` / heuristic sizing paths that don't walk the tree precisely
/// (the exact path is [`FatSizePlan`]). Budgets ~1 KiB per cluster at the
/// flavour's minimum cluster count. Unknown names fall back to FAT32's
/// floor, which is the largest of the three.
pub fn min_volume_bytes(fs_type: &str) -> u64 {
    let kind = parse_fat_kind(fs_type).unwrap_or(FatKind::Fat32);
    match kind {
        // 4084 clusters × 1 KiB would already exceed what a FAT12 volume
        // usually is; a 1 MiB floor comfortably holds the metadata plus a
        // real root directory.
        FatKind::Fat12 => 1024 * 1024,
        FatKind::Fat16 => u64::from(FatKind::Fat16.min_clusters()) * 1024,
        FatKind::Fat32 => u64::from(MIN_FAT32_CLUSTERS) * 1024,
    }
}

/// Reject a root-directory size the fixed region can't represent.
fn validate_root_entries(v: u16) -> Result<()> {
    if v == 0 || !v.is_multiple_of(ROOT_ENTRIES_PER_SECTOR) {
        return Err(crate::Error::InvalidArgument(format!(
            "fat: root_entries must be a non-zero multiple of {ROOT_ENTRIES_PER_SECTOR} \
             (got {v})"
        )));
    }
    Ok(())
}

/// The `(sectors_per_cluster, fat_size, …)` a volume of a given size
/// resolves to. Produced by [`Fat32::geometry`] and consumed both by
/// `format` and by the content-fit sizer in [`size_plan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Geometry {
    pub(crate) spc: u8,
    pub(crate) fat_size: u32,
    pub(crate) reserved: u16,
    pub(crate) root_entries: u16,
    pub(crate) clusters: u32,
}

/// Where a directory's 32-byte slots live on the device.
///
/// Unifies the two shapes a FAT directory can take: a cluster chain (every
/// directory on FAT32, every non-root directory on FAT12/16) and the
/// FAT12/16 fixed root region. Callers address slots by byte position
/// within the flattened directory and let [`DirLayout::offset_of`] map that
/// onto the device.
pub(super) struct DirLayout {
    /// `(device offset, byte length)` per chunk, in order. Every chunk is
    /// `chunk_bytes` long except possibly the last of a fixed root region.
    chunks: Vec<(u64, usize)>,
    /// Bytes per chunk — one cluster.
    chunk_bytes: usize,
    /// Clusters backing the directory, in order. Empty for the fixed root.
    clusters: Vec<u32>,
    /// The FAT12/16 fixed root region, which cannot be extended.
    fixed_root: bool,
}

impl DirLayout {
    /// Total addressable bytes of directory.
    pub(super) fn len(&self) -> usize {
        self.chunks.iter().map(|&(_, n)| n).sum()
    }

    /// Device offset of the byte at position `pos` within the directory.
    /// Panics if `pos` is past the end — callers bound it by [`Self::len`].
    pub(super) fn offset_of(&self, pos: usize) -> u64 {
        let (base, _) = self.chunks[pos / self.chunk_bytes];
        base + (pos % self.chunk_bytes) as u64
    }

    /// `true` for the FAT12/16 fixed root, which callers must not try to
    /// grow.
    pub(super) fn is_fixed_root(&self) -> bool {
        self.fixed_root
    }

    /// Last cluster of the chain, or `None` for the fixed root.
    pub(super) fn last_cluster(&self) -> Option<u32> {
        self.clusters.last().copied()
    }

    /// Append `clusters` to the chain, extending the chunk list to match.
    fn extend_with(&mut self, clusters: &[u32], offsets: impl Fn(u32) -> u64) {
        for &c in clusters {
            self.chunks.push((offsets(c), self.chunk_bytes));
            self.clusters.push(c);
        }
    }

    /// Write back the byte range `[start, end)` of the directory's flat
    /// buffer. Whole chunks are written at a time, so `bytes` must be the
    /// complete buffer, not a slice of it.
    pub(super) fn write_range(
        &self,
        dev: &mut dyn BlockDevice,
        bytes: &[u8],
        start: usize,
        end: usize,
    ) -> Result<()> {
        let first = start / self.chunk_bytes;
        let last = (end - 1) / self.chunk_bytes;
        for i in first..=last {
            let (off, n) = self.chunks[i];
            let at = i * self.chunk_bytes;
            dev.write_at(off, &bytes[at..at + n])?;
        }
        Ok(())
    }

    /// Read the whole directory into one flat buffer.
    pub(super) fn read_all(&self, dev: &mut dyn BlockDevice) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; self.len()];
        let mut at = 0usize;
        for &(off, n) in &self.chunks {
            dev.read_at(off, &mut buf[at..at + n])?;
            at += n;
        }
        Ok(buf)
    }
}

/// An open FAT12 / FAT16 / FAT32 filesystem.
///
/// The name predates FAT12/16 support; one type drives all three flavours,
/// distinguished by [`Fat32::kind`].
#[derive(Debug)]
pub struct Fat32 {
    boot: BootSector,
    fat: Fat,
    /// Cluster to hand out next from the free pool.
    next_free: u32,
    /// Pending child directory entries keyed by parent directory start
    /// cluster. Staged instead of rewriting the parent's cluster chain on
    /// every child; serialized once on eviction or at flush.
    dir_batch: DirBatch<u32, mutate::PendingEntry>,
    /// Per-directory set of names ever staged (ASCII-lowercased so the
    /// lookup matches FAT's case-insensitive comparison). Lets
    /// `child_exists` answer in O(1) instead of linearly scanning the
    /// pending batch — without it, bulk-inserting N files into one
    /// directory is O(N²). Keeping evicted-but-flushed names here too is
    /// harmless: they really do exist (on disk), so the answer is still
    /// correct.
    pending_names: std::collections::HashMap<u32, std::collections::HashSet<String>>,
}

impl Fat32 {
    /// Pick `sectors_per_cluster` for a volume of `total_sectors`, mirroring
    /// the conventional mkfs.vfat size thresholds. `pub(crate)` so the
    /// content-fit sizer ([`size_plan`]) inverts the exact same geometry.
    pub(crate) fn pick_spc(total_sectors: u32) -> u8 {
        match total_sectors {
            0..=532_480 => 1,          // ≤ 260 MiB
            532_481..=16_777_216 => 8, // ≤ 8 GiB
            16_777_217..=33_554_432 => 16,
            33_554_433..=67_108_864 => 32,
            _ => 64,
        }
    }

    /// Default fixed root-directory size for a FAT12/16 volume of
    /// `total_sectors`, following the mkfs.fat convention.
    pub(crate) fn default_root_entries(total_sectors: u32) -> u16 {
        if total_sectors <= FLOPPY_MAX_SECTORS {
            FLOPPY_ROOT_ENTRIES
        } else {
            DEFAULT_ROOT_ENTRIES
        }
    }

    /// Grow `fat_size` until the FAT is big enough to map every data
    /// cluster it leaves room for, and report the cluster count it settles
    /// on. The loop always terminates: `fat_size` strictly increases, so
    /// the metadata eventually swallows the volume and the size check
    /// fires.
    fn converge_fat_size(
        kind: FatKind,
        total_sectors: u32,
        spc: u8,
        reserved: u32,
        num_fats: u32,
        root_sectors: u32,
    ) -> Result<(u32, u32)> {
        let mut fat_size = 1u32;
        loop {
            let meta = reserved + num_fats * fat_size + root_sectors;
            if meta >= total_sectors {
                return Err(crate::Error::InvalidArgument(format!(
                    "{}: volume too small to hold the FAT metadata",
                    kind.as_str()
                )));
            }
            let clusters = (total_sectors - meta) / spc as u32;
            let needed = kind
                .fat_bytes(u64::from(clusters) + 2)
                .div_ceil(u64::from(SECTOR)) as u32;
            if needed <= fat_size {
                return Ok((fat_size, clusters));
            }
            fat_size = needed;
        }
    }

    /// Resolve the on-disk geometry for a `kind` volume of `total_sectors`.
    /// Errors if the volume can't be represented in that flavour.
    ///
    /// FAT32 keeps the conventional mkfs.vfat cluster-size thresholds
    /// ([`Self::pick_spc`]). FAT12/16 instead search upward from one sector
    /// per cluster for the smallest cluster size whose data-cluster count
    /// falls inside the flavour's band — a FAT16 volume with too many
    /// clusters isn't invalid, it just needs bigger clusters.
    ///
    /// `pub(crate)` so the content-fit sizer ([`size_plan`]) searches against
    /// the authoritative geometry rather than re-deriving it.
    pub(crate) fn geometry(
        kind: FatKind,
        total_sectors: u32,
        root_entries: Option<u16>,
    ) -> Result<Geometry> {
        let num_fats = 2u32;
        let (reserved, root_entries) = if kind == FatKind::Fat32 {
            (32u32, 0u16)
        } else {
            let re = root_entries.unwrap_or_else(|| Self::default_root_entries(total_sectors));
            validate_root_entries(re)?;
            (1u32, re)
        };
        let root_sectors = (u32::from(root_entries) * dir::ENTRY_SIZE as u32).div_ceil(SECTOR);

        // FAT32 has exactly one candidate cluster size, so its geometry (and
        // its error text) is unchanged from when this only spoke FAT32.
        if kind == FatKind::Fat32 {
            let spc = Self::pick_spc(total_sectors);
            let (fat_size, clusters) = Self::converge_fat_size(
                kind,
                total_sectors,
                spc,
                reserved,
                num_fats,
                root_sectors,
            )?;
            if clusters < MIN_FAT32_CLUSTERS {
                return Err(crate::Error::InvalidArgument(format!(
                    "fat32: {clusters} clusters is below the FAT32 minimum of \
                     {MIN_FAT32_CLUSTERS} — use a volume of at least ~33 MiB"
                )));
            }
            return Ok(Geometry {
                spc,
                fat_size,
                reserved: reserved as u16,
                root_entries,
                clusters,
            });
        }

        // Cluster sizes to try, smallest first — up to 32 KiB, the largest
        // DOS/Windows accept on FAT12/16.
        let mut smallest = None;
        for &spc in &[1u8, 2, 4, 8, 16, 32, 64] {
            // A failure here means the metadata already swallows the
            // volume; a larger cluster size only makes that worse, so
            // propagate rather than trying the next candidate.
            let (fat_size, clusters) = Self::converge_fat_size(
                kind,
                total_sectors,
                spc,
                reserved,
                num_fats,
                root_sectors,
            )?;
            smallest.get_or_insert(clusters);
            if clusters > kind.max_clusters() {
                continue; // needs bigger clusters
            }
            if clusters < kind.min_clusters() {
                break; // bigger clusters would only shrink the count further
            }
            return Ok(Geometry {
                spc,
                fat_size,
                reserved: reserved as u16,
                root_entries,
                clusters,
            });
        }
        let got = smallest.unwrap_or(0);
        if got < kind.min_clusters() {
            Err(crate::Error::InvalidArgument(format!(
                "{}: {got} clusters is below the {} minimum of {} — use a larger volume \
                 (or a smaller FAT type)",
                kind.as_str(),
                kind.as_str(),
                kind.min_clusters()
            )))
        } else {
            Err(crate::Error::InvalidArgument(format!(
                "{}: a volume of {total_sectors} sectors needs more than {} clusters even at \
                 the largest cluster size — use a wider FAT type",
                kind.as_str(),
                kind.max_clusters()
            )))
        }
    }

    /// Format a fresh, empty FAT volume onto `dev`. Writes the boot sector
    /// (plus, on FAT32, its backup and the FSInfo sectors), both FAT
    /// copies, and the empty root directory.
    pub fn format(dev: &mut dyn BlockDevice, opts: &FatFormatOpts) -> Result<Self> {
        let kind = opts.kind;
        let total = opts.total_sectors;
        let need = total as u64 * SECTOR as u64;
        if dev.total_size() < need {
            return Err(crate::Error::InvalidArgument(format!(
                "{}: device has {} bytes, need {need}",
                kind.as_str(),
                dev.total_size()
            )));
        }
        let geom = Self::geometry(kind, total, opts.root_entries)?;

        let mut boot = BootSector::defaults_for(kind);
        boot.sectors_per_cluster = geom.spc;
        boot.total_sectors = total;
        boot.fat_size = geom.fat_size;
        boot.reserved_sector_count = geom.reserved;
        boot.root_entry_count = geom.root_entries;
        boot.volume_id = opts.volume_id;
        boot.volume_label = opts.volume_label;

        // Size the in-memory table to the full on-disk FAT so encode()
        // produces exactly `fat_size` sectors.
        let fat_bytes = geom.fat_size as usize * SECTOR as usize;
        let mut fat = Fat::new(kind, fat_bytes, boot.media);
        if kind == FatKind::Fat32 {
            // Root directory occupies cluster 2, a one-cluster chain.
            fat.set(boot.root_cluster, fat.eoc());
        }

        let mut fs = Self {
            boot,
            fat,
            // FAT32 spends cluster 2 on the root directory; FAT12/16 keep
            // the root out of the data area entirely, so cluster 2 is free.
            next_free: if kind == FatKind::Fat32 { 3 } else { 2 },
            dir_batch: DirBatch::new(DEFAULT_CAPACITY),
            pending_names: std::collections::HashMap::new(),
        };
        // Zero only the metadata, not the whole device: the reserved
        // sectors + every FAT copy + (on FAT12/16) the fixed root region —
        // everything before the data area — and, on FAT32, the root
        // directory's one cluster. Data-region clusters are marked free in
        // the FAT and never read, so their prior contents are irrelevant —
        // this keeps `format` O(metadata) instead of O(device), so
        // formatting a large block device is near-instant rather than
        // writing zeros across its whole capacity. `flush` writes the boot
        // sectors, FSInfo, and both full FATs into the cleared region.
        let meta_bytes = u64::from(fs.boot.data_start_sector()) * u64::from(SECTOR);
        dev.zero_range(0, meta_bytes)?;
        if kind == FatKind::Fat32 {
            let cluster_bytes = u64::from(geom.spc) * u64::from(SECTOR);
            dev.zero_range(fs.cluster_offset(fs.boot.root_cluster), cluster_bytes)?;
        }

        // Mirror the boot-sector volume label as the first root-dir entry;
        // without this fsck.vfat treats the boot label as stale and would
        // "auto-remove" it (-n exit 1).
        let root_off = fs.root_dir_offset();
        dev.write_at(root_off, &fs.volume_label_entry())?;

        fs.flush(dev)?;
        Ok(fs)
    }

    /// Which FAT flavour this volume is.
    pub fn kind(&self) -> FatKind {
        self.boot.kind
    }

    /// Device byte offset where the root directory's first slot lives —
    /// the fixed region on FAT12/16, cluster 2 (usually) on FAT32.
    fn root_dir_offset(&self) -> u64 {
        if self.boot.kind == FatKind::Fat32 {
            self.cluster_offset(self.boot.root_cluster)
        } else {
            u64::from(self.boot.root_dir_start_sector()) * u64::from(SECTOR)
        }
    }

    /// `true` when `dir_id` names the FAT12/16 fixed root directory. That
    /// root has no cluster of its own, so it is addressed by the cluster
    /// number `0` — which `boot.root_cluster` is set to on those volumes,
    /// and which a `..` entry pointing at the root already stores.
    fn is_fixed_root(&self, dir_id: u32) -> bool {
        self.boot.kind != FatKind::Fat32 && dir_id == 0
    }

    /// Resolve a directory to the device chunks holding its 32-byte slots.
    pub(super) fn dir_layout(&self, dir_id: u32) -> Result<DirLayout> {
        let cb = self.cluster_bytes() as usize;
        if self.is_fixed_root(dir_id) {
            let total = usize::from(self.boot.root_entry_count) * dir::ENTRY_SIZE;
            let base = self.root_dir_offset();
            let mut chunks = Vec::with_capacity(total.div_ceil(cb));
            let mut at = 0usize;
            while at < total {
                let n = cb.min(total - at);
                chunks.push((base + at as u64, n));
                at += n;
            }
            return Ok(DirLayout {
                chunks,
                chunk_bytes: cb,
                clusters: Vec::new(),
                fixed_root: true,
            });
        }
        let clusters = self.fat.chain(dir_id, self.boot.cluster_count())?;
        let chunks = clusters
            .iter()
            .map(|&c| (self.cluster_offset(c), cb))
            .collect();
        Ok(DirLayout {
            chunks,
            chunk_bytes: cb,
            clusters,
            fixed_root: false,
        })
    }

    /// Grow `layout` by `n` clusters, linking them onto its chain. Errors
    /// on the FAT12/16 fixed root, which has no way to grow.
    pub(super) fn grow_dir(&mut self, layout: &mut DirLayout, n: u32) -> Result<()> {
        if layout.is_fixed_root() {
            return Err(self.fixed_root_full_err());
        }
        let extra = self.alloc_free_clusters(n)?;
        if let Some(last) = layout.last_cluster() {
            self.fat.set(last, extra[0]);
        }
        let data_start = u64::from(self.boot.data_start_sector()) * u64::from(SECTOR);
        let spc = u64::from(self.boot.sectors_per_cluster);
        layout.extend_with(&extra, |c| {
            data_start + (u64::from(c) - 2) * spc * u64::from(SECTOR)
        });
        Ok(())
    }

    /// Encode the volume-label directory entry that mirrors the boot
    /// sector's `volume_label` field.
    fn volume_label_entry(&self) -> [u8; dir::ENTRY_SIZE] {
        dir::DirEntry {
            name_83: self.boot.volume_label,
            attr: dir::ATTR_VOLUME_ID,
            first_cluster: 0,
            file_size: 0,
            mtime: 0,
        }
        .encode()
    }

    /// Absolute byte offset of a cluster's first sector.
    fn cluster_offset(&self, cluster: u32) -> u64 {
        let sector =
            self.boot.data_start_sector() + (cluster - 2) * self.boot.sectors_per_cluster as u32;
        sector as u64 * SECTOR as u64
    }

    /// Bytes per cluster.
    fn cluster_bytes(&self) -> u64 {
        self.boot.sectors_per_cluster as u64 * SECTOR as u64
    }

    /// Allocate `n` clusters, linking them into one chain, and return the
    /// chain. The last cluster's FAT entry is the end-of-chain marker.
    fn alloc_chain(&mut self, n: u32) -> Result<Vec<u32>> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let mut chain = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let c = self.next_free;
            if c as usize >= self.fat.capacity() || c >= self.boot.cluster_count() + 2 {
                return Err(crate::Error::Unsupported(format!(
                    "{}: out of clusters",
                    self.boot.kind.as_str()
                )));
            }
            chain.push(c);
            self.next_free += 1;
        }
        for w in chain.windows(2) {
            self.fat.set(w[0], w[1]);
        }
        let eoc = self.fat.eoc();
        self.fat.set(*chain.last().unwrap(), eoc);
        Ok(chain)
    }

    /// Write `data` across the cluster `chain` (the chain must be large
    /// enough). The final cluster's slack is left zero.
    fn write_chain(&self, dev: &mut dyn BlockDevice, chain: &[u32], data: &[u8]) -> Result<()> {
        let cb = self.cluster_bytes() as usize;
        for (i, &c) in chain.iter().enumerate() {
            let start = i * cb;
            if start >= data.len() {
                break;
            }
            let end = (start + cb).min(data.len());
            dev.write_at(self.cluster_offset(c), &data[start..end])?;
        }
        Ok(())
    }

    /// Persist the boot sector and every FAT copy — plus, on FAT32, the
    /// backup boot sector and both FSInfo sectors, neither of which
    /// FAT12/FAT16 has. Free-cluster accounting is derived from the current
    /// FAT, so this works for both fresh-format and modify-in-place flows.
    pub fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        // Serialize pending directory batches first — they may allocate
        // clusters, which the FAT written below must reflect.
        self.flush_dir_batches(dev)?;
        let boot_bytes = self.boot.encode();
        dev.write_at(0, &boot_bytes)?;

        if self.boot.kind == FatKind::Fat32 {
            dev.write_at(
                self.boot.backup_boot_sector as u64 * SECTOR as u64,
                &boot_bytes,
            )?;

            let clusters = self.boot.cluster_count();
            let free_count = self.count_free_clusters();
            let next_hint = if self.next_free >= 2 && self.next_free < clusters + 2 {
                self.next_free
            } else {
                2
            };
            let fsinfo = FsInfo {
                free_count,
                next_free: next_hint,
            };
            let fsinfo_bytes = fsinfo.encode();
            dev.write_at(
                self.boot.fs_info_sector as u64 * SECTOR as u64,
                &fsinfo_bytes,
            )?;
            // The backup boot region also carries a backup FSInfo at +1.
            dev.write_at(
                (self.boot.backup_boot_sector as u64 + 1) * SECTOR as u64,
                &fsinfo_bytes,
            )?;
        }

        let fat_bytes = self.fat.encode();
        for i in 0..self.boot.num_fats as u32 {
            let off = (self.boot.reserved_sector_count as u64
                + i as u64 * self.boot.fat_size as u64)
                * SECTOR as u64;
            dev.write_at(off, &fat_bytes)?;
        }
        Ok(())
    }

    /// Count clusters whose FAT entry is FREE, across the data-cluster
    /// range `[2, cluster_count + 2)`.
    fn count_free_clusters(&self) -> u32 {
        let clusters = self.boot.cluster_count();
        let mut n = 0u32;
        for c in 2..(2 + clusters) {
            if self.fat.get(c) == table::FREE {
                n += 1;
            }
        }
        n
    }

    /// One-shot: format `dev` to `total_sectors` and copy a host directory
    /// tree into the root. Symlinks and device nodes in the source are
    /// skipped (FAT has no representation for them).
    pub fn build_from_host_dir(
        dev: &mut dyn BlockDevice,
        total_sectors: u32,
        src: &Path,
        volume_id: u32,
        volume_label: [u8; 11],
    ) -> Result<()> {
        let opts = FatFormatOpts {
            total_sectors,
            volume_id,
            volume_label,
            ..Default::default()
        };
        let mut fs = Self::format(dev, &opts)?;
        fs.populate_from_host_dir(dev, src)?;
        fs.flush(dev)?;
        dev.sync()?;
        Ok(())
    }

    /// Populate an already-formatted FAT32 root with the contents of
    /// `src`. The volume label set at format time stays in place;
    /// callers that want to re-set it should re-format. Used by the
    /// repack flow where the destination has been formatted already.
    pub fn populate_from_host_dir(&mut self, dev: &mut dyn BlockDevice, src: &Path) -> Result<()> {
        let root_cluster = self.boot.root_cluster;
        // Root is its own "parent" placeholder; parent_cluster is unused when
        // is_root = true.
        self.write_dir_tree(dev, src, root_cluster, true, root_cluster)
    }

    /// Recursively populate the directory whose data starts at `dir_cluster`
    /// from the host directory `src`. `is_root` suppresses the "." / ".."
    /// entries (the FAT32 root has none).
    ///
    /// `dir_cluster` must already be a one-cluster chain; the directory is
    /// extended if its entries overflow one cluster.
    fn write_dir_tree(
        &mut self,
        dev: &mut dyn BlockDevice,
        src: &Path,
        dir_cluster: u32,
        is_root: bool,
        parent_cluster: u32,
    ) -> Result<()> {
        // Assemble the directory's 32-byte entries in memory.
        let mut entries: Vec<u8> = Vec::new();
        if is_root {
            // Mirror the boot-sector volume label as a root-dir entry; without
            // this fsck.vfat treats the boot label as stale.
            entries.extend_from_slice(&self.volume_label_entry());
        } else {
            entries.extend_from_slice(&dot_entry(b".          ", dir_cluster));
            // ".." points at the parent; a parent that is the root is
            // recorded as cluster 0 by convention.
            let pc = if parent_cluster == self.boot.root_cluster {
                0
            } else {
                parent_cluster
            };
            entries.extend_from_slice(&dot_entry(b"..         ", pc));
        }

        let mut short_seq: u32 = 0;
        let mut children: Vec<(std::path::PathBuf, std::fs::Metadata)> = Vec::new();
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            children.push((entry.path(), meta));
        }
        // Deterministic order.
        children.sort_by(|a, b| a.0.file_name().cmp(&b.0.file_name()));

        for (path, meta) in children {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| crate::Error::InvalidArgument("fat32: non-UTF-8 file name".into()))?
                .to_string();
            let ft = meta.file_type();
            if ft.is_symlink() {
                continue; // FAT has no symlinks
            }
            let mtime = mutate::host_mtime_secs(&meta);
            if ft.is_file() {
                let size = meta.len();
                let cb = self.cluster_bytes();
                let n_clusters = size.div_ceil(cb).max(1) as u32;
                let chain = self.alloc_chain(n_clusters)?;
                self.stream_file(dev, &path, &chain, size)?;
                let first = if size == 0 { 0 } else { chain[0] };
                self.push_entry(
                    &mut entries,
                    &name,
                    dir::ATTR_ARCHIVE,
                    first,
                    size as u32,
                    mtime,
                    &mut short_seq,
                );
                // A zero-length file keeps no clusters.
                if size == 0 {
                    self.free_unused_chain(&chain);
                }
            } else if ft.is_dir() {
                // Each subdirectory starts as a one-cluster chain.
                let chain = self.alloc_chain(1)?;
                let child_cluster = chain[0];
                self.write_dir_tree(dev, &path, child_cluster, false, dir_cluster)?;
                self.push_entry(
                    &mut entries,
                    &name,
                    dir::ATTR_DIRECTORY,
                    child_cluster,
                    0,
                    mtime,
                    &mut short_seq,
                );
            }
            // Other types (devices, fifos, sockets) are skipped.
        }

        self.write_dir_entries(dev, dir_cluster, &entries)?;
        Ok(())
    }

    /// Append a directory entry for `name` to `entries`, emitting LFN
    /// fragments first when the name isn't a plain 8.3 name. `mtime` is
    /// Unix epoch seconds (`0` for none).
    #[allow(clippy::too_many_arguments)]
    fn push_entry(
        &self,
        entries: &mut Vec<u8>,
        name: &str,
        attr: u8,
        first_cluster: u32,
        file_size: u32,
        mtime: u32,
        short_seq: &mut u32,
    ) {
        let upper = name.to_ascii_uppercase();
        // An LFN run is needed when the on-disk 8.3 name can't reproduce the
        // original verbatim — either because the original isn't a valid 8.3
        // name (too long, lower-case, weird chars) or because case was lost.
        let (name_83, need_lfn) = if dir::is_valid_83(&upper) {
            (dir::pack_83(&upper), upper != name)
        } else {
            let s = dir::generate_83(name, *short_seq);
            *short_seq += 1;
            (s, true)
        };
        if need_lfn {
            let csum = dir::lfn_checksum(&name_83);
            for frag in dir::encode_lfn_run(name, csum) {
                entries.extend_from_slice(&frag);
            }
        }
        let entry = dir::DirEntry {
            name_83,
            attr,
            first_cluster,
            file_size,
            mtime,
        };
        entries.extend_from_slice(&entry.encode());
    }

    /// Write a directory's assembled entry bytes into its cluster chain,
    /// extending the chain if the entries overflow `dir_cluster`'s single
    /// cluster.
    ///
    /// The FAT12/16 fixed root is written as one flat region instead: it
    /// can't be extended, so entries that don't fit are an error rather
    /// than a cluster allocation.
    fn write_dir_entries(
        &mut self,
        dev: &mut dyn BlockDevice,
        dir_cluster: u32,
        entries: &[u8],
    ) -> Result<()> {
        let cb = self.cluster_bytes() as usize;
        if self.is_fixed_root(dir_cluster) {
            let capacity = usize::from(self.boot.root_entry_count) * dir::ENTRY_SIZE;
            if entries.len() > capacity {
                return Err(self.fixed_root_full_err());
            }
            // Pad to the whole region so stale slots read as end-of-directory.
            let mut buf = entries.to_vec();
            buf.resize(capacity, 0);
            dev.write_at(self.root_dir_offset(), &buf)?;
            return Ok(());
        }
        let need_clusters = entries.len().div_ceil(cb).max(1) as u32;
        let mut chain = vec![dir_cluster];
        // Extend if more than one cluster of entries.
        if need_clusters > 1 {
            let extra = self.alloc_chain(need_clusters - 1)?;
            // Link dir_cluster -> extra[0] -> ... -> EOC.
            self.fat.set(dir_cluster, extra[0]);
            chain.extend_from_slice(&extra);
        }
        // Pad to a whole number of clusters with zero (free entries).
        let mut buf = entries.to_vec();
        buf.resize(need_clusters as usize * cb, 0);
        self.write_chain(dev, &chain, &buf)?;
        Ok(())
    }

    /// The error a full FAT12/16 fixed root produces. Unlike every other
    /// FAT directory it cannot be extended, so overflowing it is a hard
    /// failure rather than a cluster allocation.
    pub(super) fn fixed_root_full_err(&self) -> crate::Error {
        crate::Error::Unsupported(format!(
            "{}: the root directory is fixed at {} entries and is full — reformat with a \
             larger `-O root_entries=`, nest the files in a subdirectory, or use fat32",
            self.boot.kind.as_str(),
            self.boot.root_entry_count
        ))
    }

    /// Stream a host file's bytes into its cluster chain. The file is read
    /// one cluster at a time — never fully resident in memory.
    fn stream_file(
        &self,
        dev: &mut dyn BlockDevice,
        host: &Path,
        chain: &[u32],
        size: u64,
    ) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        let cb = self.cluster_bytes() as usize;
        let mut file = std::fs::File::open(host)?;
        let mut buf = vec![0u8; cb];
        let mut remaining = size;
        for &c in chain {
            let want = remaining.min(cb as u64) as usize;
            buf[..want].fill(0);
            file.read_exact(&mut buf[..want])?;
            dev.write_at(self.cluster_offset(c), &buf[..want])?;
            remaining -= want as u64;
            if remaining == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Return clusters allocated for a zero-length file to the free pool.
    /// Only valid for the most-recently-allocated chain (we just rewind
    /// `next_free`); used right after `alloc_chain` for empty files.
    fn free_unused_chain(&mut self, chain: &[u32]) {
        for &c in chain {
            self.fat.set(c, table::FREE);
        }
        // The chain was the tail of the free pool — rewind.
        if let Some(&first) = chain.first()
            && first + chain.len() as u32 == self.next_free
        {
            self.next_free = first;
        }
    }

    // -- read path --------------------------------------------------------

    /// Open an existing FAT12 / FAT16 / FAT32 volume from `dev`: decode the
    /// boot sector, derive the flavour from its cluster count, and load the
    /// primary FAT into memory.
    pub fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        let mut bs = [0u8; 512];
        dev.read_at(0, &mut bs)?;
        // `decode` already rejects a BPB whose sector size, cluster size or
        // FAT count would break the cluster arithmetic, so everything read
        // back here is within its declared bounds.
        let boot = BootSector::decode(&bs)?;
        let kind = boot.kind;
        if boot.bytes_per_sector as u32 != SECTOR {
            return Err(crate::Error::Unsupported(format!(
                "{}: only 512-byte sectors are supported (got {})",
                kind.as_str(),
                boot.bytes_per_sector
            )));
        }
        // Validate the on-disk geometry before sizing any allocation from
        // the untrusted FAT-size field. The FAT(s) plus reserved sectors and
        // the fixed root region must fit inside the declared volume, and the
        // volume must fit on the device.
        let total_sectors = boot.total_sectors as u64;
        let volume_bytes = total_sectors.checked_mul(SECTOR as u64).ok_or_else(|| {
            crate::Error::InvalidImage(format!("{}: total_sectors overflow", kind.as_str()))
        })?;
        if volume_bytes > dev.total_size() {
            return Err(crate::Error::InvalidImage(format!(
                "{}: volume of {volume_bytes} bytes exceeds device size {}",
                kind.as_str(),
                dev.total_size()
            )));
        }
        let meta_sectors = u64::from(boot.data_start_sector());
        if meta_sectors > total_sectors {
            return Err(crate::Error::InvalidImage(format!(
                "{}: reserved + FATs + root ({meta_sectors} sectors) overruns volume of \
                 {total_sectors} sectors",
                kind.as_str()
            )));
        }
        // Read the first FAT copy. `fat_size` is now bounded by the volume,
        // which is bounded by the device, so this allocation is safe.
        let fat_bytes_len = boot.fat_size as u64 * SECTOR as u64;
        let mut fat_bytes = vec![0u8; fat_bytes_len as usize];
        let fat_off = boot.reserved_sector_count as u64 * SECTOR as u64;
        dev.read_at(fat_off, &mut fat_bytes)?;
        let fat = Fat::decode(kind, &fat_bytes);
        // For an opened volume we don't track a free-pool cursor; set it
        // past the end so accidental allocation needs an explicit reset.
        let next_free = fat.capacity() as u32;
        Ok(Self {
            boot,
            fat,
            next_free,
            dir_batch: DirBatch::new(DEFAULT_CAPACITY),
            pending_names: std::collections::HashMap::new(),
        })
    }

    /// The boot sector — exposed read-only for callers (e.g. `fstool info`).
    pub fn boot_sector(&self) -> &BootSector {
        &self.boot
    }

    /// In-memory FAT — exposed read-only for diagnostics.
    pub fn fat(&self) -> &Fat {
        &self.fat
    }

    /// Mutable access to the in-memory FAT — used by the modify-in-place
    /// file handle to grow / shrink cluster chains.
    pub(super) fn fat_mut(&mut self) -> &mut Fat {
        &mut self.fat
    }

    /// Hint the free-cluster scanner to consider `cluster` next. Used when
    /// the file handle frees a tail of clusters during a shrink so the
    /// allocator can hand them out again.
    pub(super) fn hint_next_free(&mut self, cluster: u32) {
        if cluster >= 2 && cluster < self.boot.cluster_count() + 2 {
            self.next_free = cluster;
        }
    }

    /// Walk the cluster chain starting at `start`, collecting every cluster
    /// in order.
    pub fn chain_of(&self, start: u32) -> Result<Vec<u32>> {
        self.fat.chain(start, self.boot.cluster_count())
    }

    /// List the entries of a directory by absolute path. `/` resolves to
    /// the root directory. Returns one [`crate::fs::DirEntry`] per visible
    /// entry, with `inode` set to the entry's `first_cluster` (FAT has no
    /// inode numbers, but the cluster number is a stable per-entry id).
    /// Volume-label entries and `.` / `..` are skipped.
    pub fn list_path(
        &self,
        dev: &mut dyn BlockDevice,
        path: &str,
    ) -> Result<Vec<crate::fs::DirEntry>> {
        let cluster = self.resolve_dir(dev, path)?;
        self.list_cluster(dev, cluster)
    }

    /// Open a regular file by absolute path for streaming reads. The
    /// returned reader holds an in-memory copy of the cluster chain and
    /// borrows `dev` for the actual block reads.
    pub fn open_file_reader<'a>(
        &self,
        dev: &'a mut dyn BlockDevice,
        path: &str,
    ) -> Result<FatFileReader<'a>> {
        let (entry, dir_cluster) = self.resolve_entry(dev, path)?;
        if entry.attr & dir::ATTR_DIRECTORY != 0 {
            return Err(crate::Error::InvalidArgument(format!(
                "fat32: {path:?} is a directory, not a file"
            )));
        }
        let _ = dir_cluster; // unused once we have the leaf
        let chain = if entry.first_cluster < 2 {
            Vec::new() // zero-length file
        } else {
            self.chain_of(entry.first_cluster)?
        };
        let cluster_bytes = self.cluster_bytes();
        let data_start = self.boot.data_start_sector() as u64 * SECTOR as u64;
        let spc = self.boot.sectors_per_cluster;
        Ok(FatFileReader {
            dev,
            chain,
            cluster_bytes,
            data_start,
            spc,
            remaining: entry.file_size as u64,
            cluster_idx: 0,
            cluster_off: 0,
        })
    }

    /// Resolve `path` to the cluster number of the named directory, or the
    /// root cluster for `/` / "".
    pub fn resolve_dir(&self, dev: &mut dyn BlockDevice, path: &str) -> Result<u32> {
        let parts = split_path(path);
        let mut cluster = self.boot.root_cluster;
        for part in parts {
            let entries = self.list_cluster_raw(dev, cluster)?;
            let next = entries
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(part))
                .ok_or_else(|| {
                    crate::Error::InvalidArgument(format!(
                        "fat32: no such entry {part:?} under {path:?}"
                    ))
                })?;
            if next.1.attr & dir::ATTR_DIRECTORY == 0 {
                return Err(crate::Error::InvalidArgument(format!(
                    "fat32: {part:?} is not a directory"
                )));
            }
            // For ".." pointing at the root, the on-disk first_cluster is 0.
            cluster = if next.1.first_cluster == 0 {
                self.boot.root_cluster
            } else {
                next.1.first_cluster
            };
        }
        Ok(cluster)
    }

    /// Resolve `path` to its 8.3 entry plus the cluster of the containing
    /// directory. Errors if the path is `/` (root has no entry).
    pub fn resolve_entry(
        &self,
        dev: &mut dyn BlockDevice,
        path: &str,
    ) -> Result<(dir::DirEntry, u32)> {
        let parts = split_path(path);
        if parts.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "fat32: cannot resolve root \"/\" as a file entry".into(),
            ));
        }
        let mut cluster = self.boot.root_cluster;
        let (last, prefix) = parts.split_last().unwrap();
        for part in prefix {
            let entries = self.list_cluster_raw(dev, cluster)?;
            let next = entries
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(part))
                .ok_or_else(|| {
                    crate::Error::InvalidArgument(format!(
                        "fat32: no such entry {part:?} under {path:?}"
                    ))
                })?;
            cluster = if next.1.first_cluster == 0 {
                self.boot.root_cluster
            } else {
                next.1.first_cluster
            };
        }
        let entries = self.list_cluster_raw(dev, cluster)?;
        let found = entries
            .into_iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(last))
            .ok_or_else(|| {
                crate::Error::InvalidArgument(format!(
                    "fat32: no such entry {last:?} under {path:?}"
                ))
            })?;
        Ok((found.1, cluster))
    }

    /// Read every 32-byte slot of the directory at `dir_cluster` — walking
    /// its cluster chain to the end, or spanning the fixed root region on
    /// FAT12/16. Returns the raw bytes concatenated.
    fn read_dir_bytes(&self, dev: &mut dyn BlockDevice, dir_cluster: u32) -> Result<Vec<u8>> {
        self.dir_layout(dir_cluster)?.read_all(dev)
    }

    /// Walk a directory's slots, reassembling LFN runs into long names.
    /// Returns `(long-or-short-name, entry)` pairs in on-disk order,
    /// excluding the volume-label entry and `.` / `..`.
    fn list_cluster_raw(
        &self,
        dev: &mut dyn BlockDevice,
        dir_cluster: u32,
    ) -> Result<Vec<(String, dir::DirEntry)>> {
        let bytes = self.read_dir_bytes(dev, dir_cluster)?;
        let mut out = Vec::new();
        let mut lfn_run: Vec<dir::LfnFragment> = Vec::new();
        for slot in bytes.as_chunks::<{ dir::ENTRY_SIZE }>().0 {
            match dir::classify_slot(slot) {
                dir::RawSlot::End => break,
                dir::RawSlot::Deleted => {
                    lfn_run.clear();
                }
                dir::RawSlot::Lfn(frag) => {
                    lfn_run.push(frag);
                }
                dir::RawSlot::ShortEntry(entry) => {
                    if entry.attr & dir::ATTR_VOLUME_ID != 0
                        && entry.attr & dir::ATTR_DIRECTORY == 0
                    {
                        // Volume label entry.
                        lfn_run.clear();
                        continue;
                    }
                    let short_name = entry.short_name_string();
                    if short_name == "." || short_name == ".." {
                        lfn_run.clear();
                        continue;
                    }
                    let name = dir::assemble_lfn(&lfn_run, &entry.name_83)
                        .unwrap_or_else(|| short_name.clone());
                    lfn_run.clear();
                    out.push((name, entry));
                }
            }
        }
        Ok(out)
    }

    /// List the entries of `dir_cluster` as generic [`crate::fs::DirEntry`]s.
    fn list_cluster(
        &self,
        dev: &mut dyn BlockDevice,
        dir_cluster: u32,
    ) -> Result<Vec<crate::fs::DirEntry>> {
        use crate::fs::{DirEntry as FsDirEntry, EntryKind};
        let entries = self.list_cluster_raw(dev, dir_cluster)?;
        Ok(entries
            .into_iter()
            .map(|(name, e)| {
                let is_dir = e.attr & dir::ATTR_DIRECTORY != 0;
                FsDirEntry {
                    name,
                    inode: e.first_cluster,
                    kind: if is_dir {
                        EntryKind::Dir
                    } else {
                        EntryKind::Regular
                    },
                    size: if is_dir { 0 } else { u64::from(e.file_size) },
                }
            })
            .collect())
    }
}

/// Split an absolute or relative FAT path into its non-empty components.
/// `/`, `""`, and `.` all yield an empty vec (= "the root").
fn split_path(path: &str) -> Vec<&str> {
    path.split(['/', '\\'])
        .filter(|p| !p.is_empty() && *p != ".")
        .collect()
}

/// Streaming reader for a FAT32 file. Walks the cluster chain on demand;
/// the file's bytes are never buffered beyond one [`std::io::Read::read`]
/// call's destination buffer.
pub struct FatFileReader<'a> {
    dev: &'a mut dyn BlockDevice,
    chain: Vec<u32>,
    cluster_bytes: u64,
    data_start: u64,
    spc: u8,
    /// Bytes of the file still to be returned.
    remaining: u64,
    /// Index into `chain` of the cluster currently being read from.
    cluster_idx: usize,
    /// Byte offset into the current cluster.
    cluster_off: u64,
}

impl<'a> std::io::Read for FatFileReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 || self.cluster_idx >= self.chain.len() {
            return Ok(0);
        }
        let avail_in_cluster = self.cluster_bytes - self.cluster_off;
        let want = (buf.len() as u64).min(avail_in_cluster).min(self.remaining) as usize;
        let cluster = self.chain[self.cluster_idx];
        let cluster_start =
            self.data_start + (cluster as u64 - 2) * self.spc as u64 * SECTOR as u64;
        let off = cluster_start + self.cluster_off;
        self.dev
            .read_at(off, &mut buf[..want])
            .map_err(std::io::Error::other)?;
        self.cluster_off += want as u64;
        self.remaining -= want as u64;
        if self.cluster_off == self.cluster_bytes {
            self.cluster_idx += 1;
            self.cluster_off = 0;
        }
        Ok(want)
    }
}

/// Build a "." or ".." directory entry (11-byte raw name, directory attr).
fn dot_entry(name_83: &[u8; 11], cluster: u32) -> [u8; dir::ENTRY_SIZE] {
    dir::DirEntry {
        name_83: *name_83,
        attr: dir::ATTR_DIRECTORY,
        first_cluster: cluster,
        file_size: 0,
        mtime: 0,
    }
    .encode()
}

// ----------------------------------------------------------------------
// `crate::fs::Filesystem` trait impl — lets `Fat32` be driven by the
// generic walker in `crate::repack` alongside the other writable FSes.
// ----------------------------------------------------------------------

impl crate::fs::FilesystemFactory for Fat32 {
    type FormatOpts = FatFormatOpts;

    fn format(dev: &mut dyn BlockDevice, opts: &Self::FormatOpts) -> Result<Self> {
        Self::format(dev, opts)
    }

    fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        Self::open(dev)
    }
}

impl crate::fs::Filesystem for Fat32 {
    fn create_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
        src: crate::fs::FileSource,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("fat32: non-UTF-8 path".into()))?;
        let (mut reader, len) = src.open()?;
        self.add_file_from_reader(dev, s, &mut reader, len, meta.mtime)
    }

    fn create_file_streaming(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
        body: &mut dyn std::io::Read,
        len: u64,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("fat32: non-UTF-8 path".into()))?;
        self.add_file_from_reader(dev, s, body, len, meta.mtime)
    }

    fn create_dir(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("fat32: non-UTF-8 path".into()))?;
        self.add_dir(dev, s, meta.mtime)
    }

    fn create_symlink(
        &mut self,
        _dev: &mut dyn BlockDevice,
        _path: &Path,
        _target: &Path,
        _meta: crate::fs::FileMeta,
    ) -> Result<()> {
        Err(crate::Error::Unsupported(
            "fat32: filesystem does not support symbolic links".into(),
        ))
    }

    fn create_device(
        &mut self,
        _dev: &mut dyn BlockDevice,
        _path: &Path,
        _kind: crate::fs::DeviceKind,
        _major: u32,
        _minor: u32,
        _meta: crate::fs::FileMeta,
    ) -> Result<()> {
        Err(crate::Error::Unsupported(
            "fat32: filesystem does not support device / FIFO / socket nodes".into(),
        ))
    }

    fn remove(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("fat32: non-UTF-8 path".into()))?;
        self.remove(dev, s)
    }

    fn list(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<Vec<crate::fs::DirEntry>> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("fat32: non-UTF-8 path".into()))?;
        // Materialize staged directory entries so the listing (and any
        // ancestor lookups along the way) reflect them.
        self.flush_dir_batches(dev)?;
        self.list_path(dev, s)
    }

    /// Surface the entry's modification time. The trait default fills the
    /// timestamps with zeros (a `DirEntry` carries none); FAT stores a DOS
    /// date/time in the 8.3 entry, so decode it here. FAT has no per-file
    /// atime time-of-day or distinct ctime, so all three report the write
    /// time (atime/ctime are stored from the same value on create).
    fn getattr(&mut self, dev: &mut dyn BlockDevice, path: &Path) -> Result<crate::fs::FileAttrs> {
        use crate::fs::{EntryKind, FileAttrs};
        if path == Path::new("/") || path.as_os_str().is_empty() {
            return Ok(FileAttrs::defaults_for(EntryKind::Dir, 0, 0));
        }
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("fat32: non-UTF-8 path".into()))?;
        // A freshly `put` file may still be staged; materialize first.
        self.flush_dir_batches(dev)?;
        let (entry, _dir_cluster) = self.resolve_entry(dev, s)?;
        let kind = if entry.attr & dir::ATTR_DIRECTORY != 0 {
            EntryKind::Dir
        } else {
            EntryKind::Regular
        };
        let mut attrs = FileAttrs::defaults_for(kind, u64::from(entry.file_size), 0);
        // FAT has no Unix mode; derive read/write permission from the only
        // bit it does carry — ATTR_READ_ONLY. A set read-only bit drops the
        // write bits (0o444 / 0o555); otherwise the kind-appropriate default
        // from `defaults_for` (0o644 / 0o755) stands.
        if entry.attr & dir::ATTR_READ_ONLY != 0 {
            attrs.mode = match kind {
                EntryKind::Dir => 0o555,
                _ => 0o444,
            };
        }
        attrs.mtime = entry.mtime;
        attrs.atime = entry.mtime;
        attrs.ctime = entry.mtime;
        Ok(attrs)
    }

    /// Update attributes on `path`. FAT carries no Unix mode, uid, or gid,
    /// so the only attribute we can honour from a `chmod` is the requested
    /// mode's owner-write bit, which maps onto the directory entry's
    /// `ATTR_READ_ONLY` bit: a mode with no owner-write (`0o200` clear) sets
    /// read-only; otherwise it clears read-only. uid/gid are silently
    /// ignored (FAT has no owners). The write date/time is left intact when
    /// only the attribute byte changes.
    ///
    /// TODO: honour `attrs.mtime` by rewriting the entry's write date/time
    /// (via `unix_to_dos_datetime`) when set; today only the mode is applied.
    fn set_attrs(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
        attrs: crate::fs::SetAttrs,
    ) -> Result<()> {
        let Some(mode) = attrs.mode else {
            // Nothing FAT can represent was requested (uid/gid/times only).
            return Ok(());
        };
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("fat32: non-UTF-8 path".into()))?;
        // No owner-write bit → read-only; otherwise writable.
        let read_only = (mode & 0o200) == 0;
        self.set_entry_readonly(dev, s, read_only)
    }

    fn read_file<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &Path,
    ) -> Result<Box<dyn Read + 'a>> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("fat32: non-UTF-8 path".into()))?;
        // The lookup path reads directory entries straight from disk, so
        // a file freshly created via `create_file_*` is invisible until
        // its parent directory's batch is serialised. `list` / `open_file_rw`
        // already flush for the same reason; do it here too so callers like
        // `FsSink::materialise_copy` can read back a just-written file.
        self.flush_dir_batches(dev)?;
        let r = self.open_file_reader(dev, s)?;
        Ok(Box::new(r))
    }

    fn open_file_ro<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &Path,
    ) -> Result<Box<dyn crate::fs::FileReadHandle + 'a>> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("fat32: non-UTF-8 path".into()))?;
        let (parent_cluster, leaf) = self.resolve_parent(dev, s)?;
        let found = self
            .find_entry(dev, parent_cluster, &leaf)?
            .ok_or_else(|| crate::Error::InvalidArgument(format!("fat32: {s:?} not found")))?;
        if found.entry.attr & dir::ATTR_DIRECTORY != 0 {
            return Err(crate::Error::InvalidArgument(format!(
                "fat32: {s:?} is a directory, not a file"
            )));
        }
        let mutate::FoundEntry {
            layout,
            entry_pos,
            entry,
            ..
        } = found;
        let inner = handle::FatFileHandle::open_existing(self, dev, &layout, entry_pos, entry)?;
        Ok(Box::new(handle::ReadOnlyFatHandle::new(inner)))
    }

    fn open_file_rw<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &Path,
        flags: crate::fs::OpenFlags,
        meta: Option<crate::fs::FileMeta>,
    ) -> Result<Box<dyn crate::fs::FileHandle + 'a>> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("fat32: non-UTF-8 path".into()))?;
        // This path locates directory entries on disk (and the handle
        // updates them in place), so serialize any staged entries first.
        self.flush_dir_batches(dev)?;
        // Resolve the parent + leaf. We do this once up front so the
        // create-then-reopen branch shares the result.
        let (parent_cluster, leaf) = self.resolve_parent(dev, s)?;
        let existing = self.find_entry(dev, parent_cluster, &leaf)?;
        let found = match existing {
            Some(f) => {
                if f.entry.attr & dir::ATTR_DIRECTORY != 0 {
                    return Err(crate::Error::InvalidArgument(format!(
                        "fat32: {s:?} is a directory, not a file"
                    )));
                }
                f
            }
            None => {
                if !flags.create {
                    return Err(crate::Error::InvalidArgument(format!(
                        "fat32: {s:?} not found and `create` is false"
                    )));
                }
                if meta.is_none() {
                    return Err(crate::Error::InvalidArgument(
                        "fat32: open_file_rw with create=true requires meta".into(),
                    ));
                }
                // Create an empty file via the existing modify-in-place
                // path; serialize it so its on-disk entry exists, then
                // re-find it (the handle updates that entry in place).
                let mtime = meta.as_ref().map(|m| m.mtime).unwrap_or(0);
                self.add_file_from_reader(dev, s, &mut std::io::empty(), 0, mtime)?;
                self.flush_dir_batches(dev)?;
                self.find_entry(dev, parent_cluster, &leaf)?
                    .ok_or_else(|| {
                        crate::Error::InvalidImage(
                            "fat32: created file disappeared before open".into(),
                        )
                    })?
            }
        };
        let mutate::FoundEntry {
            layout,
            entry_pos,
            entry,
            ..
        } = found;
        let mut handle =
            handle::FatFileHandle::open_existing(self, dev, &layout, entry_pos, entry)?;
        if flags.truncate {
            crate::fs::FileHandle::set_len(&mut handle, 0)?;
        }
        if flags.append {
            // Position at end so the first write appends.
            use std::io::Seek as _;
            let len = crate::fs::FileHandle::len(&handle);
            handle
                .seek(std::io::SeekFrom::Start(len))
                .map_err(crate::Error::Io)?;
        }
        Ok(Box::new(handle))
    }

    fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        Self::flush(self, dev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;
    use crate::fs::{FileMeta, FileSource, Filesystem, OpenFlags};
    use std::io::{Seek as _, SeekFrom, Write as _};

    /// Format a fresh 48 MiB FAT32 volume in memory; return (dev, fs).
    fn fresh_volume() -> (MemoryBackend, Fat32) {
        let mut dev = MemoryBackend::new(48 * 1024 * 1024);
        let opts = FatFormatOpts {
            total_sectors: 48 * 1024 * 1024 / 512,
            volume_id: 0xCAFE_F00D,
            volume_label: *b"OPENRWTEST ",
            ..Default::default()
        };
        let fs = Fat32::format(&mut dev, &opts).unwrap();
        (dev, fs)
    }

    /// Read a whole file by path into a Vec via the streaming reader.
    fn read_all(fs: &mut Fat32, dev: &mut dyn BlockDevice, path: &str) -> Vec<u8> {
        let mut r = fs
            .open_file_reader(dev, path)
            .expect("open_file_reader for read_all");
        let mut out = Vec::new();
        r.read_to_end(&mut out).expect("read_to_end");
        out
    }

    #[test]
    fn geometry_small_volume() {
        // 64 MiB volume = 131072 sectors.
        let g = Fat32::geometry(FatKind::Fat32, 131072, None).unwrap();
        assert_eq!(g.spc, 1);
        assert!(g.fat_size > 0);
        assert!(g.clusters >= MIN_FAT32_CLUSTERS);
        // Consistency: reserved + 2*fat + clusters*spc <= total.
        assert!(32 + 2 * g.fat_size + g.clusters * g.spc as u32 <= 131072);
        // The FAT must map every cluster.
        assert!(g.fat_size * (SECTOR / 4) >= g.clusters + 2);
    }

    #[test]
    fn geometry_rejects_tiny_volume() {
        // 4 MiB is far below the FAT32 minimum.
        assert!(Fat32::geometry(FatKind::Fat32, 8192, None).is_err());
    }

    #[test]
    fn format_empty_volume() {
        let mut dev = MemoryBackend::new(48 * 1024 * 1024);
        let opts = FatFormatOpts {
            total_sectors: 48 * 1024 * 1024 / 512,
            volume_id: 0xCAFE_F00D,
            volume_label: *b"TESTVOL    ",
            ..Default::default()
        };
        let fs = Fat32::format(&mut dev, &opts).unwrap();
        // Boot sector round-trips.
        let mut bs = [0u8; 512];
        dev.read_at(0, &mut bs).unwrap();
        let decoded = BootSector::decode(&bs).unwrap();
        assert_eq!(decoded.total_sectors, opts.total_sectors);
        assert_eq!(decoded.root_cluster, 2);
        assert_eq!(decoded.volume_id, 0xCAFE_F00D);
        // Backup boot sector matches.
        let mut backup = [0u8; 512];
        dev.read_at(6 * 512, &mut backup).unwrap();
        assert_eq!(bs, backup);
        // Root cluster's FAT entry is an end-of-chain marker.
        assert!(fs.fat.is_eoc(fs.fat.get(2)));
    }

    #[test]
    fn open_rejects_oversized_fat_size() {
        // A malicious fat_size_32 (sectors per FAT) must not size a huge
        // allocation; `open` should reject it before allocating the FAT.
        let (mut dev, _fs) = fresh_volume();
        let mut bs = [0u8; 512];
        dev.read_at(0, &mut bs).unwrap();
        // fat_size_32 lives at byte offset 36.
        bs[36..40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        dev.write_at(0, &bs).unwrap();
        match Fat32::open(&mut dev) {
            Err(crate::Error::InvalidImage(_)) => {}
            other => panic!("expected InvalidImage, got {other:?}"),
        }
    }

    #[test]
    fn open_file_rw_partial_write_round_trip() {
        let (mut dev, mut fs) = fresh_volume();
        // Initial contents: 200 bytes of 0xAA.
        let initial = vec![0xAAu8; 200];
        fs.create_file(
            &mut dev,
            Path::new("hello.bin"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(initial.clone())),
                len: 200,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();

        // Reopen rw and patch 16 bytes at offset 100.
        let patch = [0x55u8; 16];
        {
            let mut h = fs
                .open_file_rw(&mut dev, Path::new("hello.bin"), OpenFlags::default(), None)
                .unwrap();
            h.seek(SeekFrom::Start(100)).unwrap();
            h.write_all(&patch).unwrap();
            h.sync().unwrap();
        }

        let got = read_all(&mut fs, &mut dev, "hello.bin");
        assert_eq!(got.len(), 200);
        // 0..100 unchanged.
        assert!(got[..100].iter().all(|&b| b == 0xAA));
        // 100..116 patched.
        assert_eq!(&got[100..116], &patch);
        // 116..200 unchanged.
        assert!(got[116..].iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn set_attrs_read_only_round_trip() {
        use crate::fs::SetAttrs;
        let (mut dev, mut fs) = fresh_volume();
        // Create a file with a real mtime so we can confirm it survives the
        // attribute flip (the entry's write date/time must not be clobbered).
        let mtime = 1_615_779_298u32;
        fs.create_file(
            &mut dev,
            Path::new("ro.txt"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(vec![0x42u8; 64])),
                len: 64,
            },
            FileMeta {
                mtime,
                ..FileMeta::default()
            },
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();

        // Baseline: a writable file reports 0o644 (FAT 2s resolution rounds
        // the odd second down, so compare against the rounded value).
        let base = fs.getattr(&mut dev, Path::new("ro.txt")).unwrap();
        assert_eq!(base.mode, 0o644);
        let want_mtime = base.mtime;
        assert_ne!(want_mtime, 0);

        // chmod 0o444 → read-only set; reopen the volume and confirm.
        fs.set_attrs(
            &mut dev,
            Path::new("ro.txt"),
            SetAttrs {
                mode: Some(0o444),
                ..SetAttrs::default()
            },
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();
        let mut fs = Fat32::open(&mut dev).unwrap();
        let a = fs.getattr(&mut dev, Path::new("ro.txt")).unwrap();
        assert_eq!(a.mode, 0o444);
        // The write time must be intact — only the attr byte changed.
        assert_eq!(a.mtime, want_mtime);

        // chmod 0o644 → read-only cleared; reopen and confirm.
        fs.set_attrs(
            &mut dev,
            Path::new("ro.txt"),
            SetAttrs {
                mode: Some(0o644),
                ..SetAttrs::default()
            },
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();
        let mut fs = Fat32::open(&mut dev).unwrap();
        let a = fs.getattr(&mut dev, Path::new("ro.txt")).unwrap();
        assert_eq!(a.mode, 0o644);
        assert_eq!(a.mtime, want_mtime);
    }

    #[test]
    fn open_file_rw_extends_file() {
        let (mut dev, mut fs) = fresh_volume();
        let initial = vec![0x11u8; 50];
        fs.create_file(
            &mut dev,
            Path::new("grow.bin"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(initial)),
                len: 50,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();

        // Seek past EOF and write 1 KiB of pattern.
        let pattern: Vec<u8> = (0..1024u32).map(|i| (i & 0xFF) as u8).collect();
        {
            let mut h = fs
                .open_file_rw(&mut dev, Path::new("grow.bin"), OpenFlags::default(), None)
                .unwrap();
            assert_eq!(h.len(), 50);
            h.seek(SeekFrom::Start(2000)).unwrap();
            h.write_all(&pattern).unwrap();
            // len() = 2000 + 1024 = 3024.
            assert_eq!(h.len(), 2000 + 1024);
            h.sync().unwrap();
        }

        let got = read_all(&mut fs, &mut dev, "grow.bin");
        assert_eq!(got.len(), 3024);
        // First 50 bytes preserved.
        assert!(got[..50].iter().all(|&b| b == 0x11));
        // Gap 50..2000 is zero.
        assert!(got[50..2000].iter().all(|&b| b == 0));
        // Patched range matches.
        assert_eq!(&got[2000..], &pattern[..]);
    }

    #[test]
    fn open_file_rw_set_len_grow_and_shrink() {
        let (mut dev, mut fs) = fresh_volume();
        let initial = vec![0x77u8; 128];
        fs.create_file(
            &mut dev,
            Path::new("resize.bin"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(initial)),
                len: 128,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();

        // Grow to 4096 bytes — added bytes must read as zero.
        {
            let mut h = fs
                .open_file_rw(
                    &mut dev,
                    Path::new("resize.bin"),
                    OpenFlags::default(),
                    None,
                )
                .unwrap();
            h.set_len(4096).unwrap();
            assert_eq!(h.len(), 4096);
            h.sync().unwrap();
        }
        let after_grow = read_all(&mut fs, &mut dev, "resize.bin");
        assert_eq!(after_grow.len(), 4096);
        assert!(after_grow[..128].iter().all(|&b| b == 0x77));
        assert!(after_grow[128..].iter().all(|&b| b == 0));

        // Shrink back to 64 — truncation discards trailing bytes.
        {
            let mut h = fs
                .open_file_rw(
                    &mut dev,
                    Path::new("resize.bin"),
                    OpenFlags::default(),
                    None,
                )
                .unwrap();
            h.set_len(64).unwrap();
            assert_eq!(h.len(), 64);
            h.sync().unwrap();
        }
        let after_shrink = read_all(&mut fs, &mut dev, "resize.bin");
        assert_eq!(after_shrink.len(), 64);
        assert!(after_shrink.iter().all(|&b| b == 0x77));
    }

    #[test]
    fn open_file_rw_append() {
        let (mut dev, mut fs) = fresh_volume();
        let initial = b"head".to_vec();
        fs.create_file(
            &mut dev,
            Path::new("app.txt"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(initial.clone())),
                len: initial.len() as u64,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();

        {
            let mut h = fs
                .open_file_rw(
                    &mut dev,
                    Path::new("app.txt"),
                    OpenFlags {
                        append: true,
                        ..OpenFlags::default()
                    },
                    None,
                )
                .unwrap();
            h.write_all(b"-tail").unwrap();
            h.sync().unwrap();
        }
        let got = read_all(&mut fs, &mut dev, "app.txt");
        assert_eq!(got, b"head-tail");
    }

    #[test]
    fn open_file_rw_create_new() {
        let (mut dev, mut fs) = fresh_volume();
        // The path doesn't exist yet — `create: true` should make it.
        {
            let mut h = fs
                .open_file_rw(
                    &mut dev,
                    Path::new("brand-new.dat"),
                    OpenFlags {
                        create: true,
                        ..OpenFlags::default()
                    },
                    Some(FileMeta::default()),
                )
                .unwrap();
            assert_eq!(h.len(), 0);
            h.write_all(b"hello from rw create").unwrap();
            h.sync().unwrap();
        }
        let got = read_all(&mut fs, &mut dev, "brand-new.dat");
        assert_eq!(got, b"hello from rw create");

        // Without `create`, a non-existent path is an error.
        match fs.open_file_rw(&mut dev, Path::new("never.bin"), OpenFlags::default(), None) {
            Ok(_) => panic!("expected error for non-existent path with create=false"),
            Err(crate::Error::InvalidArgument(_)) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    /// Batched directory writes: create a directory with many files in
    /// one session (accumulated in the dir batch, serialized once at
    /// flush), reopen, and confirm every file lists and reads back.
    #[test]
    fn batched_many_files_one_dir_round_trip() {
        let (mut dev, mut fs) = fresh_volume();
        fs.create_dir(&mut dev, Path::new("/d"), FileMeta::default())
            .unwrap();
        let n = 50usize;
        for i in 0..n {
            let body = format!("file-body-{i:03}");
            fs.create_file(
                &mut dev,
                &std::path::PathBuf::from(format!("/d/f{i:03}.txt")),
                FileSource::Reader {
                    reader: Box::new(std::io::Cursor::new(body.clone().into_bytes())),
                    len: body.len() as u64,
                },
                FileMeta::default(),
            )
            .unwrap();
        }
        fs.flush(&mut dev).unwrap();

        let mut fs2 = Fat32::open(&mut dev).unwrap();
        let listed: std::collections::HashSet<String> =
            crate::fs::Filesystem::list(&mut fs2, &mut dev, Path::new("/d"))
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect();
        assert_eq!(listed.len(), n, "expected {n} files, got {listed:?}");
        for i in 0..n {
            let name = format!("f{i:03}.txt");
            assert!(listed.contains(&name), "missing {name}");
            let got = read_all(&mut fs2, &mut dev, &format!("/d/{name}"));
            assert_eq!(got, format!("file-body-{i:03}").into_bytes());
        }
    }

    #[test]
    fn open_file_ro_random_seek_fat() {
        use std::io::Read as _;
        let (mut dev, mut fs) = fresh_volume();
        // Write a file spanning a couple clusters with a recognisable pattern.
        let data: Vec<u8> = (0..16_384u32).map(|i| (i & 0xFF) as u8).collect();
        fs.create_file(
            &mut dev,
            Path::new("ro.bin"),
            FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(data.clone())),
                len: data.len() as u64,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();

        let mut h = fs
            .open_file_ro(&mut dev, Path::new("ro.bin"))
            .expect("open_file_ro");
        assert_eq!(h.len(), data.len() as u64);
        assert!(!h.is_empty());

        // Read at offset 9000 — a non-zero, non-cluster-aligned position.
        h.seek(SeekFrom::Start(9000)).unwrap();
        let mut buf = [0u8; 64];
        h.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[9000..9064]);

        // Seek back to a different offset and re-read.
        h.seek(SeekFrom::Start(123)).unwrap();
        let mut buf2 = [0u8; 32];
        h.read_exact(&mut buf2).unwrap();
        assert_eq!(&buf2[..], &data[123..155]);
    }
}
