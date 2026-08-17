//! Content-fit size estimator for FAT12 / FAT16 / FAT32.
//!
//! [`FatSizePlan`] accumulates the exact cluster allocation `Fat32::format` +
//! the populate path will use for a source tree, then searches against
//! `Fat32::geometry` to return the smallest image of the chosen flavour that
//! holds it. Used by `fstool create -t fat32 <dir>` (and `-t fat12` /
//! `-t fat16`) so the output is sized to the content instead of requiring an
//! explicit `--size`.
//!
//! The model is exact up to FAT's own rounding:
//!
//! - **Data clusters** = `Σ ceil(file_len / cluster) + Σ dir_clusters`, where a
//!   directory holds `2` slots (`.`/`..`; root holds `1` for its volume label)
//!   plus `1 + lfn_slots(name)` per child and `1` end-marker slot, each slot 32
//!   bytes, rounded up to whole clusters (min one cluster per directory). On
//!   FAT12/16 the root directory is *not* charged to the data area at all — it
//!   lives in the fixed region — but it does bound how many root entries fit,
//!   so the plan grows `root_entries` to match instead.
//! - **Cluster size** depends on the volume size, which depends on the cluster
//!   count — resolved by the same fixed-point as `geometry`.
//! - **Total** = `reserved + 2 · fat_size + root_sectors + data_clusters · spc`
//!   sectors, floored at the flavour's minimum cluster count (~33 MiB for
//!   FAT32).

use std::collections::HashMap;

use super::dir::{ENTRY_SIZE, LFN_CHARS_PER_ENTRY, is_valid_83};
use super::table::FatKind;
use super::{Fat32, SECTOR};
use crate::fs::{FsSizePlan, split_parent_name};

/// Number of FAT copies — matches `Fat32::geometry`.
const NUM_FATS: u32 = 2;

/// Number of 32-byte directory slots a child named `name` consumes: one short
/// (8.3) entry plus a long-name run when the name isn't a valid 8.3 name.
fn slots_for_name(name: &str) -> u64 {
    let lfn = if is_valid_83(name) {
        0
    } else {
        let units = name.encode_utf16().count();
        units.div_ceil(LFN_CHARS_PER_ENTRY) as u64
    };
    1 + lfn
}

/// Accumulator implementing [`FsSizePlan`] for a FAT volume.
#[derive(Debug)]
pub struct FatSizePlan {
    /// Which flavour the estimate is for.
    kind: FatKind,
    /// Regular-file (and symlink-as-file) byte lengths — kept individually so
    /// per-file cluster rounding can be recomputed at the chosen cluster size.
    file_lens: Vec<u64>,
    /// Directory path → number of 32-byte slots used (entries + end marker).
    dir_slots: HashMap<String, u64>,
}

impl Default for FatSizePlan {
    fn default() -> Self {
        Self::new()
    }
}

impl FatSizePlan {
    /// A fresh FAT32 plan with just the root directory (seeded with its
    /// volume-label slot plus an end marker).
    #[must_use]
    pub fn new() -> Self {
        Self::for_kind(FatKind::Fat32)
    }

    /// A fresh plan sized for `kind`.
    #[must_use]
    pub fn for_kind(kind: FatKind) -> Self {
        let mut dir_slots = HashMap::new();
        // Root has no `.`/`..`, but the writer stores a volume-label entry.
        dir_slots.insert("/".to_string(), 1u64);
        Self {
            kind,
            file_lens: Vec::new(),
            dir_slots,
        }
    }

    /// Add one directory-entry slot run to `path`'s parent directory.
    fn charge_parent(&mut self, path: &str) {
        let (parent, name) = split_parent_name(path);
        *self.dir_slots.entry(parent.to_string()).or_insert(0) += slots_for_name(name);
    }

    /// Slots the root directory needs, including its end-of-directory
    /// marker. On FAT12/16 this sizes the fixed root region rather than
    /// charging the data area.
    fn root_slots(&self) -> u64 {
        self.dir_slots.get("/").copied().unwrap_or(1) + 1
    }

    /// The fixed root-directory size a FAT12/16 image needs to hold this
    /// tree's root entries, rounded up to the sector-aligned granularity
    /// `geometry` requires. `None` on FAT32, whose root is a cluster chain.
    fn root_entries(&self) -> Option<u16> {
        if self.kind == FatKind::Fat32 {
            return None;
        }
        let per_sector = u64::from(SECTOR) / ENTRY_SIZE as u64;
        let sectors = self.root_slots().div_ceil(per_sector).max(1);
        // Never shrink below the format default — a tiny tree still gets a
        // conventionally-sized root — and never exceed what the field holds.
        let want = (sectors * per_sector).clamp(224, u64::from(u16::MAX / 16 * 16));
        Some(want as u16)
    }

    /// Total clusters the content needs at sectors-per-cluster `spc`.
    fn clusters_at(&self, spc: u64) -> u64 {
        let cluster_bytes = spc * u64::from(SECTOR);
        let mut clusters = 0u64;
        for &len in &self.file_lens {
            clusters += len.div_ceil(cluster_bytes); // empty file → 0 clusters
        }
        for (path, &slots) in &self.dir_slots {
            // The FAT12/16 root lives outside the data area entirely.
            if path == "/" && self.kind != FatKind::Fat32 {
                continue;
            }
            // +1 slot for the trailing end-of-directory marker; at least one
            // cluster per directory.
            let bytes = (slots + 1) * ENTRY_SIZE as u64;
            clusters += bytes.div_ceil(cluster_bytes).max(1);
        }
        clusters
    }
}

impl FsSizePlan for FatSizePlan {
    fn add_dir(&mut self, path: &str) {
        self.charge_parent(path);
        // The directory itself starts with `.` and `..`.
        self.dir_slots.entry(path.to_string()).or_insert(2);
    }

    fn add_file(&mut self, path: &str, len: u64) {
        self.charge_parent(path);
        self.file_lens.push(len);
    }

    fn add_symlink(&mut self, path: &str, target: &str) {
        // FAT has no symlinks; the populate path stores the target as a small
        // file's contents at most. Charge a parent slot + the target bytes so
        // the image always fits whether the writer stores or skips it.
        self.charge_parent(path);
        self.file_lens.push(target.len() as u64);
    }

    fn add_device(&mut self, path: &str) {
        // No data clusters, but the directory entry still costs a slot.
        self.charge_parent(path);
    }

    fn total_size(&self) -> u64 {
        // Start from a closed-form lower bound, then grow the total until the
        // authoritative `Fat32::geometry` yields enough usable clusters. Using
        // the real geometry (rather than re-deriving it) guarantees the size we
        // return is one the formatter accepts — its FAT-size feedback loop
        // reserves slightly more than a naive inverse would.
        let kind = self.kind;
        let floor_clusters = u64::from(kind.min_clusters());
        let reserved = if kind == FatKind::Fat32 { 32u64 } else { 1u64 };
        let root_entries = self.root_entries();
        let root_sectors =
            u64::from(root_entries.unwrap_or(0)) * ENTRY_SIZE as u64 / u64::from(SECTOR);

        let spc0 = 1u64;
        let need0 = self.clusters_at(spc0).max(floor_clusters);
        let fat0 = kind.fat_bytes(need0 + 2).div_ceil(u64::from(SECTOR));
        let mut total = reserved + u64::from(NUM_FATS) * fat0 + root_sectors + need0 * spc0;

        for _ in 0..64 {
            let ts = u32::try_from(total).unwrap_or(u32::MAX);
            match Fat32::geometry(kind, ts, root_entries) {
                Ok(g) => {
                    let g_spc = u64::from(g.spc);
                    let need = self.clusters_at(g_spc).max(floor_clusters);
                    if u64::from(g.clusters) >= need {
                        return total * u64::from(SECTOR);
                    }
                    // Grow by the cluster deficit (plus one, so FAT-size growth
                    // can't stall the loop on a boundary).
                    total += (need - u64::from(g.clusters)) * g_spc + 1;
                }
                Err(_) => {
                    // Below the flavour's minimum: jump to a floor that
                    // geometry will accept, then let the loop refine.
                    let fat_floor = kind
                        .fat_bytes(floor_clusters + 2)
                        .div_ceil(u64::from(SECTOR));
                    let floor =
                        reserved + u64::from(NUM_FATS) * fat_floor + root_sectors + floor_clusters;
                    total = total.max(floor) + 1;
                }
            }
        }
        total * u64::from(SECTOR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_is_fat32_minimum() {
        let plan = FatSizePlan::new();
        let size = plan.total_size();
        // Floor: MIN_FAT32_CLUSTERS data clusters at spc=1 + metadata, ~33 MiB.
        assert!(size >= u64::from(crate::fs::fat::MIN_FAT32_CLUSTERS) * 512);
        assert!(
            size < 40 * 1024 * 1024,
            "empty FAT32 should be ~33 MiB, got {size}"
        );
    }

    #[test]
    fn slots_for_name_short_vs_long() {
        assert_eq!(slots_for_name("README"), 1); // valid 8.3 → no LFN
        assert_eq!(slots_for_name("KERNEL.IMG"), 1);
        // 20-char name → 1 short + ceil(20/13)=2 LFN slots.
        assert_eq!(slots_for_name("a-twenty-char-name!!"), 3);
    }

    #[test]
    fn large_content_exceeds_floor_and_grows_monotonically() {
        let mut small = FatSizePlan::new();
        for i in 0..10 {
            small.add_file(&format!("/f{i}.bin"), 1024);
        }
        let mut big = FatSizePlan::new();
        for i in 0..10 {
            big.add_file(&format!("/f{i}.bin"), 4 * 1024 * 1024 * 1024);
        }
        assert!(big.total_size() > small.total_size());
        // 40 GiB of content forces a larger sectors-per-cluster than 1.
        assert!(big.total_size() > 40u64 * 1024 * 1024 * 1024);
    }

    #[test]
    fn estimated_size_actually_fits_and_reads_back() {
        // End-to-end: size a real tree, format at exactly that size, populate,
        // and read a file back — proving the estimate is sufficient (the build
        // never runs out of space) without needing `fsck.vfat` in CI.
        use crate::block::MemoryBackend;
        use crate::fs::fat::{Fat32, FatFormatOpts};
        use crate::repack::{Source, populate_fat32_from_source};

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        for i in 0..30 {
            std::fs::write(
                dir.path().join(format!("sub/file_{i}.txt")),
                format!("contents of file {i}\n"),
            )
            .unwrap();
        }
        std::fs::write(dir.path().join("big.bin"), vec![7u8; 200_000]).unwrap();

        let src = Source::HostDir(dir.path().to_path_buf());
        let bytes = crate::analyze::size_for_source(&src, "fat32")
            .unwrap()
            .unwrap();

        let mut dev = MemoryBackend::new(bytes);
        let opts = FatFormatOpts {
            total_sectors: (bytes / 512) as u32,
            volume_id: 0,
            volume_label: *b"NO NAME    ",
            ..Default::default()
        };
        let mut fat = Fat32::format(&mut dev, &opts).unwrap();
        populate_fat32_from_source(&mut dev, &mut fat, &src).expect("populate must fit");
        fat.flush(&mut dev).unwrap();

        let fat = Fat32::open(&mut dev).unwrap();
        let mut out = Vec::new();
        let mut r = fat.open_file_reader(&mut dev, "/sub/file_3.txt").unwrap();
        std::io::Read::read_to_end(&mut r, &mut out).unwrap();
        assert_eq!(out, b"contents of file 3\n");
    }

    #[test]
    fn directories_charge_their_parent() {
        let mut plan = FatSizePlan::new();
        plan.add_dir("/sub");
        plan.add_file("/sub/a.txt", 10);
        // /sub exists with its own slots, root charged for the /sub entry.
        assert!(plan.dir_slots.contains_key("/sub"));
        assert!(plan.dir_slots["/"] > 1); // volume label + /sub
    }
}
