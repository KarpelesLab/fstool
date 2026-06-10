//! Content-fit size plan for NTFS.
//!
//! NTFS has no fixed metadata zone — the formatter lays the system files
//! ($Boot, $MFTMirr, $LogFile, $AttrDef, $UpCase, $Secure) down on demand and
//! the writer grows the `$MFT` and `$Bitmap` as content lands. The plan
//! reproduces that allocation in clusters (4 KiB by default):
//!
//! * **$MFT** — one 1024-byte record per entry plus the 16 reserved system
//!   records. The writer grows the MFT by *doubling* its data region (leaking
//!   the prior extents), so the region settles at `16·2^k` clusters — the next
//!   doubling that holds the needed record count.
//! * **File data** — a file whose body fits the resident-`$DATA` budget of its
//!   1 KiB record (≈ 700 bytes, exact against the name length) stays resident
//!   and costs no clusters; otherwise `ceil(len / cluster)` clusters.
//! * **Directory index** — children pack into the resident `$INDEX_ROOT` until
//!   it would exceed the root budget; past that the directory is promoted to a
//!   B-tree of 4 KiB `INDX` blocks (one cluster each).
//! * **$Bitmap** — one bit per cluster, resolved by a short fixed point.
//!
//! Phase 1 ([`add_dir`]/[`add_file`]/…) accumulates records, data clusters and
//! per-directory index bytes; phase 2 ([`total_size`]) folds in the doubling
//! MFT region, the fixed system files and the size-dependent bitmap.
//!
//! A safe upper bound: index-block and MFT-bitmap growth use conservative fills
//! so the writer never overflows the computed size (validated round-trip and
//! `ntfsfix`/`ntfs-3g`-clean where available).
//!
//! [`add_dir`]: crate::fs::FsSizePlan::add_dir
//! [`add_file`]: crate::fs::FsSizePlan::add_file
//! [`total_size`]: NtfsSizePlan::total_size

use std::collections::HashMap;

use super::format::FormatOpts;
use crate::fs::{FsSizePlan, split_parent_name};

/// 1024-byte MFT record (`DEFAULT_MFT_RECORD_SIZE`).
const MFT_RECORD: u64 = 1024;
/// Records 0..=15 are reserved system files (`FIRST_USER_RECORD`).
const SYSTEM_RECORDS: u64 = 16;
/// Initial `$MFT` size in clusters (`INITIAL_MFT_CLUSTERS`).
const INITIAL_MFT_CLUSTERS: u64 = 16;
/// Transient build headroom: the writer briefly needs a spare MFT-doubling
/// unit's worth of free clusters mid-build (relocating the `$MFT` `$BITMAP`,
/// staging the next record run) that end up free in the finished volume.
/// Reserving it keeps the tightest single-file images from failing to build.
const BUILD_HEADROOM_CLUSTERS: u64 = INITIAL_MFT_CLUSTERS;
/// `$LogFile` size (`LOGFILE_BYTES`).
const LOGFILE_BYTES: u64 = 64 * 1024;
/// `$UpCase` payload (64K UTF-16 code units).
const UPCASE_BYTES: u64 = 128 * 1024;

/// Per-directory index accumulator.
#[derive(Default, Clone, Copy)]
struct Dir {
    /// Σ over children of the index-entry size (`round8(16 + filename value)`).
    index_bytes: u64,
}

/// Exact-ish (safe upper bound) NTFS size accumulator.
pub struct NtfsSizePlan {
    cluster_size: u64,
    /// MFT records in use: 16 system records + one per entry.
    mft_records: u64,
    /// Clusters for non-resident file data.
    data_clusters: u64,
    /// Per-directory index byte totals (keyed by canonical path).
    dirs: HashMap<String, Dir>,
}

impl NtfsSizePlan {
    /// `$INDEX_ROOT` promotes to `$INDEX_ALLOCATION` past this many entry bytes
    /// (writer's `MAX_INDEX_ROOT_BYTES`).
    const MAX_INDEX_ROOT_BYTES: u64 = 512;

    #[must_use]
    pub fn new(opts: &FormatOpts) -> Self {
        let cluster_size = u64::from(opts.bytes_per_sector) * u64::from(opts.sectors_per_cluster);
        let mut dirs = HashMap::new();
        dirs.insert("/".to_string(), Dir::default());
        Self {
            cluster_size: cluster_size.max(512),
            mft_records: SYSTEM_RECORDS,
            data_clusters: 0,
            dirs,
        }
    }

    fn round8(n: u64) -> u64 {
        (n + 7) & !7
    }

    /// Name length in UTF-16 code units.
    fn name_units(name: &str) -> u64 {
        name.encode_utf16().count() as u64
    }

    /// `$FILE_NAME` attribute value: 66-byte fixed header + 2·name.
    fn file_name_value_len(name_units: u64) -> u64 {
        66 + 2 * name_units
    }

    /// An index entry: 16-byte header + the `$FILE_NAME` key, padded to 8.
    fn index_entry_size(name_units: u64) -> u64 {
        Self::round8(16 + Self::file_name_value_len(name_units))
    }

    /// Resident-`$DATA` budget of a 1 KiB record for a `name_units`-named file
    /// (mirrors the writer: record − header(64) − $SI(96) − $FN − $DATA hdr(24)
    /// − terminator slack(16)).
    fn resident_budget(name_units: u64) -> u64 {
        let fn_attr = 24 + Self::round8(Self::file_name_value_len(name_units));
        MFT_RECORD.saturating_sub(64 + 96 + fn_attr + 24 + 16)
    }

    /// Charge `path`'s parent directory for the index entry of this child.
    fn charge_parent(&mut self, path: &str) {
        let (parent, name) = split_parent_name(path);
        let entry = Self::index_entry_size(Self::name_units(name));
        self.dirs.entry(parent.to_string()).or_default().index_bytes += entry;
    }

    /// Clusters a directory's index needs: 0 while it fits the resident root,
    /// else a conservative B-tree of one-cluster `INDX` blocks.
    fn dir_index_clusters(&self, d: &Dir) -> u64 {
        if d.index_bytes <= Self::MAX_INDEX_ROOT_BYTES {
            return 0;
        }
        // Leaf INDX block usable bytes: block − INDX/USA header(64) −
        // terminator(16); reserve a conservative margin for separator pull-ups
        // and padding so greedy packing never overflows.
        let leaf_usable = self.cluster_size.saturating_sub(64 + 16) * 7 / 8;
        let leaves = d.index_bytes.div_ceil(leaf_usable.max(1)).max(1);
        // Internal levels: each separator entry is small; fan-out is large.
        let mut internal = 0u64;
        let mut level = leaves;
        while level > 1 {
            level = level.div_ceil(28);
            internal += level;
        }
        leaves + internal
    }

    /// The doubling `$MFT` data region: `16·2^k` clusters, the smallest that
    /// holds `mft_records` (matches `extend_mft`).
    fn mft_clusters(&self) -> u64 {
        let recs_per_cluster = self.cluster_size / MFT_RECORD;
        let mut clusters = INITIAL_MFT_CLUSTERS;
        while clusters * recs_per_cluster < self.mft_records {
            clusters *= 2;
        }
        clusters
    }

    /// `$MFT`'s own `$BITMAP` (1 bit per record), with the writer's doubling
    /// slack folded in.
    fn mft_bitmap_clusters(&self) -> u64 {
        let recs = self.mft_clusters() * (self.cluster_size / MFT_RECORD);
        (recs.div_ceil(8).div_ceil(self.cluster_size)).max(1) * 2
    }

    fn clusters_for(&self, len: u64) -> u64 {
        len.div_ceil(self.cluster_size)
    }

    /// `$Bitmap` clusters for a volume of `total_clusters`.
    fn bitmap_clusters(&self, total_clusters: u64) -> u64 {
        total_clusters.div_ceil(8).div_ceil(self.cluster_size)
    }
}

impl FsSizePlan for NtfsSizePlan {
    fn add_dir(&mut self, path: &str) {
        self.charge_parent(path);
        self.mft_records += 1;
        self.dirs.entry(path.to_string()).or_default();
    }

    fn add_file(&mut self, path: &str, len: u64) {
        self.charge_parent(path);
        self.mft_records += 1;
        let name = path.rsplit('/').next().unwrap_or("");
        if len > Self::resident_budget(Self::name_units(name)) {
            self.data_clusters += self.clusters_for(len);
        }
    }

    fn add_symlink(&mut self, path: &str, _target: &str) {
        // Symlinks are reparse points: the target lives in a resident
        // $REPARSE_POINT attribute, so no data clusters.
        self.charge_parent(path);
        self.mft_records += 1;
    }

    fn add_device(&mut self, path: &str) {
        self.charge_parent(path);
        self.mft_records += 1;
    }

    fn total_size(&self) -> u64 {
        let dir_index: u64 = self.dirs.values().map(|d| self.dir_index_clusters(d)).sum();

        // Fixed system files (clusters): $Boot(1) + $MFTMirr(1) + $LogFile +
        // $AttrDef(1) + $UpCase + $Secure:$SDS(1).
        let fixed = 1
            + 1
            + LOGFILE_BYTES.div_ceil(self.cluster_size)
            + 1
            + UPCASE_BYTES.div_ceil(self.cluster_size)
            + 1;

        let core = fixed
            + self.mft_clusters()
            + self.mft_bitmap_clusters()
            + self.data_clusters
            + dir_index;

        // Resolve the $Bitmap fixed point (its size depends on the cluster
        // count), then reserve one trailing cluster for the backup boot sector.
        let mut total = core + self.bitmap_clusters(core + 1);
        for _ in 0..8 {
            let next = core + self.bitmap_clusters(total);
            if next <= total {
                break;
            }
            total = next;
        }
        // + the transient build headroom + one trailing cluster (backup boot).
        (total + BUILD_HEADROOM_CLUSTERS + 1) * self.cluster_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_volume_is_small() {
        let p = NtfsSizePlan::new(&FormatOpts::default());
        // $UpCase(32) + $LogFile(16) + MFT(16) + a few → well under 4 MiB.
        let mib = p.total_size() / (1024 * 1024);
        assert!(mib < 4, "empty NTFS plan should be < 4 MiB, got {mib}");
    }

    #[test]
    fn small_files_stay_resident() {
        let mut p = NtfsSizePlan::new(&FormatOpts::default());
        for i in 0..50 {
            p.add_file(&format!("/f{i}"), 100);
        }
        assert_eq!(p.data_clusters, 0, "tiny files should be resident");
    }

    #[test]
    fn large_file_adds_clusters() {
        let mut p = NtfsSizePlan::new(&FormatOpts::default());
        p.add_file("/big", 1_000_000);
        assert_eq!(p.data_clusters, 1_000_000u64.div_ceil(4096));
    }

    #[test]
    fn many_records_double_the_mft() {
        let mut p = NtfsSizePlan::new(&FormatOpts::default());
        let base = p.mft_clusters();
        for i in 0..5000 {
            p.add_file(&format!("/file_{i:05}.txt"), 0);
        }
        assert!(p.mft_clusters() > base);
        // 16 + 5000 records → 5016 → next 16·2^k·4 ≥ 5016 → 2048 clusters.
        assert_eq!(p.mft_clusters(), 2048);
    }

    #[test]
    fn big_directory_promotes() {
        let mut p = NtfsSizePlan::new(&FormatOpts::default());
        for i in 0..400 {
            p.add_file(&format!("/file_{i:04}"), 0);
        }
        let root = p.dirs.get("/").unwrap();
        assert!(
            p.dir_index_clusters(root) > 0,
            "400 children should promote"
        );
    }

    #[test]
    fn monotonic_in_size() {
        let small = {
            let mut p = NtfsSizePlan::new(&FormatOpts::default());
            p.add_file("/a", 5000);
            p.total_size()
        };
        let big = {
            let mut p = NtfsSizePlan::new(&FormatOpts::default());
            p.add_file("/a", 50_000_000);
            p.total_size()
        };
        assert!(big > small);
    }
}
