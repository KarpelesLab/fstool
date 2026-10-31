//! Read-only filesystem verification: bounded, structured diagnostics.
//!
//! A verifier walks a filesystem's on-disk metadata without changing a
//! byte and reports what it finds as a list of [`Diagnostic`]s — each
//! with a [`Severity`], a machine-readable [`DiagCode`], the
//! [`Location`] of the object at fault and a human-readable message.
//!
//! Every verifier is *bounded*: [`VerifyOpts`] caps the number of
//! diagnostics kept and the number of metadata nodes, records and
//! extents visited, and the memory spent on the allocation cross-check.
//! A hostile image (a B-tree whose sibling links form a cycle, a
//! billion-record catalog, an extent list that never ends) therefore
//! cannot make verification run unbounded. When a bound is hit the
//! walk stops at that point and the report says so in
//! [`VerifyReport::truncated`] — an incomplete check is never presented
//! as a clean one ([`VerifyReport::is_clean`] is false while anything
//! was truncated).
//!
//! Verification never repairs. A repair, like a resize, needs its own
//! explicit plan and a recoverable transaction boundary; see
//! [`crate::fs::resize`].
//!
//! Supported today: HFS+ / HFSX ([`crate::fs::hfs_plus::verify`]) and
//! FAT12/16/32 ([`crate::fs::fat::verify`]).

use std::fmt;

/// How serious a [`Diagnostic`] is.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational: something worth knowing that is not a defect
    /// (an optional structure that is absent, a check that was skipped).
    Info,
    /// Unusual but tolerated by the native tools: a stale alternate
    /// header field, a dirty-but-replayable journal.
    Warning,
    /// A defect: the native checker (`fsck_hfs`, `fsck.vfat`) would
    /// report the volume as needing repair.
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        })
    }
}

/// What a [`Diagnostic`] is about. Shared by every verifier; each
/// filesystem uses the subset that applies to it. New codes are added
/// as verifiers learn new checks, hence `#[non_exhaustive]`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagCode {
    // --- superblock / volume header -----------------------------------
    /// The primary superblock / volume header could not be read or
    /// decoded at all.
    HeaderUnreadable,
    /// A header field holds an impossible value (block size, counts).
    HeaderFieldInvalid,
    /// The volume claims more bytes than its device holds.
    VolumeLargerThanDevice,
    /// The alternate (backup) header is missing or undecodable.
    AlternateHeaderMissing,
    /// The alternate header disagrees with the primary on a structural
    /// field (block size, block count, special-file extents).
    AlternateHeaderMismatch,
    /// The volume is not marked cleanly unmounted.
    VolumeDirty,
    /// The volume carries the "inconsistent" flag a kernel sets after
    /// detecting damage.
    VolumeInconsistent,
    /// The journal holds transactions not yet replayed: the on-disk
    /// metadata (and therefore this report) predates them.
    JournalNotEmpty,
    /// The journal or its info block is malformed or unsupported.
    JournalInvalid,
    // --- allocation -----------------------------------------------------
    /// An extent reaches past the last allocation block.
    ExtentOutOfRange,
    /// Two objects (or one object twice) claim the same allocation block.
    ExtentOverlap,
    /// A fork's recorded block count disagrees with the sum of its
    /// extents, or its logical size exceeds its physical size.
    ForkSizeMismatch,
    /// A fork's extent list is malformed (gaps in the overflow records,
    /// a non-zero extent after a terminator).
    ForkExtentsInvalid,
    /// The allocation bitmap / table is too small for the volume, or
    /// lies outside it.
    BitmapInvalid,
    /// Blocks marked allocated that no object owns (leaked; reclaimed
    /// by the native checker as a minor repair).
    BitmapLeakedBlocks,
    /// Blocks an object owns that the bitmap marks free — the dangerous
    /// direction: the next allocation would overwrite live data.
    BitmapMissingAllocation,
    /// The header's free-block count disagrees with the bitmap.
    FreeCountMismatch,
    /// A block the format reserves (boot blocks, the volume headers) is
    /// not marked allocated.
    ReservedBlockFree,
    // --- B-trees ---------------------------------------------------------
    /// A B-tree header record is unreadable or holds impossible values.
    BTreeHeaderInvalid,
    /// A node descriptor has the wrong kind or height for its place in
    /// the tree, or the node could not be read.
    BTreeNodeInvalid,
    /// A node's record-offset table is malformed.
    BTreeRecordOffsets,
    /// A record key is malformed or too long.
    BTreeKeyInvalid,
    /// Keys are not in strictly ascending order.
    BTreeKeyOrder,
    /// An index record's key differs from its child's first key.
    BTreeIndexKeyMismatch,
    /// Forward/backward sibling links are broken.
    BTreeSiblingLink,
    /// The tree's depth, leaf count or first/last leaf in the header
    /// record disagree with the tree itself.
    BTreeHeaderMismatch,
    /// The node-allocation map disagrees with the nodes in use.
    BTreeNodeMap,
    // --- catalog / directory ---------------------------------------------
    /// A catalog / directory record is malformed.
    RecordInvalid,
    /// A file or folder record without its thread record (or the reverse).
    ThreadMissing,
    /// A thread record that points at the wrong parent or name.
    ThreadMismatch,
    /// Two records carry the same object id.
    DuplicateId,
    /// An object id at or past the volume's next-id counter, or in the
    /// reserved range.
    IdOutOfRange,
    /// A folder's recorded child count differs from its children.
    ValenceMismatch,
    /// The header's file or folder count disagrees with the catalog.
    CountMismatch,
    /// A record (extents overflow, attribute) refers to an object that
    /// does not exist.
    OrphanRecord,
    /// A hard link's target is missing or its link count is wrong.
    LinkCountMismatch,
    /// The root directory is missing or malformed.
    RootMissing,
    /// A cluster chain is broken: it loops, runs into a free or bad
    /// cluster, or ends early / late for the size it carries.
    ChainInvalid,
    /// The allocation tables (FAT copies) disagree with each other.
    TableCopiesDiffer,
    // --- meta ----------------------------------------------------------
    /// A feature this verifier does not check; the report is complete
    /// for everything else.
    Unsupported,
}

impl DiagCode {
    /// Stable kebab-case name, as printed by `fstool check`.
    pub fn name(self) -> &'static str {
        use DiagCode::*;
        match self {
            HeaderUnreadable => "header-unreadable",
            HeaderFieldInvalid => "header-field-invalid",
            VolumeLargerThanDevice => "volume-larger-than-device",
            AlternateHeaderMissing => "alternate-header-missing",
            AlternateHeaderMismatch => "alternate-header-mismatch",
            VolumeDirty => "volume-dirty",
            VolumeInconsistent => "volume-inconsistent",
            JournalNotEmpty => "journal-not-empty",
            JournalInvalid => "journal-invalid",
            ExtentOutOfRange => "extent-out-of-range",
            ExtentOverlap => "extent-overlap",
            ForkSizeMismatch => "fork-size-mismatch",
            ForkExtentsInvalid => "fork-extents-invalid",
            BitmapInvalid => "bitmap-invalid",
            BitmapLeakedBlocks => "bitmap-leaked-blocks",
            BitmapMissingAllocation => "bitmap-missing-allocation",
            FreeCountMismatch => "free-count-mismatch",
            ReservedBlockFree => "reserved-block-free",
            BTreeHeaderInvalid => "btree-header-invalid",
            BTreeNodeInvalid => "btree-node-invalid",
            BTreeRecordOffsets => "btree-record-offsets",
            BTreeKeyInvalid => "btree-key-invalid",
            BTreeKeyOrder => "btree-key-order",
            BTreeIndexKeyMismatch => "btree-index-key-mismatch",
            BTreeSiblingLink => "btree-sibling-link",
            BTreeHeaderMismatch => "btree-header-mismatch",
            BTreeNodeMap => "btree-node-map",
            RecordInvalid => "record-invalid",
            ThreadMissing => "thread-missing",
            ThreadMismatch => "thread-mismatch",
            DuplicateId => "duplicate-id",
            IdOutOfRange => "id-out-of-range",
            ValenceMismatch => "valence-mismatch",
            CountMismatch => "count-mismatch",
            OrphanRecord => "orphan-record",
            LinkCountMismatch => "link-count-mismatch",
            RootMissing => "root-missing",
            ChainInvalid => "chain-invalid",
            TableCopiesDiffer => "table-copies-differ",
            Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for DiagCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Where a [`Diagnostic`] points. Every field is optional; a verifier
/// fills in what identifies the object best.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Location {
    /// The on-disk structure, e.g. `"volume-header"`, `"catalog"`,
    /// `"extents-overflow"`, `"attributes"`, `"allocation-bitmap"`, `"fat"`.
    pub structure: Option<&'static str>,
    /// Byte offset from the start of the volume.
    pub byte_offset: Option<u64>,
    /// Allocation block / cluster number.
    pub block: Option<u64>,
    /// Number of blocks the problem spans, starting at `block`.
    pub block_count: Option<u64>,
    /// B-tree node number.
    pub node: Option<u32>,
    /// Record index within the node.
    pub record: Option<u32>,
    /// Object id: HFS+ CNID, FAT first cluster, ext inode.
    pub object_id: Option<u64>,
}

impl Location {
    /// A location naming only a structure.
    pub fn structure(s: &'static str) -> Self {
        Self {
            structure: Some(s),
            ..Self::default()
        }
    }

    /// Set the byte offset.
    pub fn at_byte(mut self, off: u64) -> Self {
        self.byte_offset = Some(off);
        self
    }

    /// Set the block range.
    pub fn blocks(mut self, start: u64, count: u64) -> Self {
        self.block = Some(start);
        self.block_count = Some(count);
        self
    }

    /// Set the node (and optionally record) number.
    pub fn node(mut self, node: u32, record: Option<u32>) -> Self {
        self.node = Some(node);
        self.record = record;
        self
    }

    /// Set the object id.
    pub fn object(mut self, id: u64) -> Self {
        self.object_id = Some(id);
        self
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        if let Some(s) = self.structure {
            parts.push(s.to_string());
        }
        if let Some(n) = self.node {
            parts.push(format!("node {n}"));
        }
        if let Some(r) = self.record {
            parts.push(format!("record {r}"));
        }
        if let Some(id) = self.object_id {
            parts.push(format!("id {id}"));
        }
        match (self.block, self.block_count) {
            (Some(b), Some(c)) if c > 1 => parts.push(format!("blocks {b}..{}", b + c)),
            (Some(b), _) => parts.push(format!("block {b}")),
            _ => {}
        }
        if let Some(o) = self.byte_offset {
            parts.push(format!("byte {o}"));
        }
        f.write_str(&parts.join(", "))
    }
}

/// One finding.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// How serious it is.
    pub severity: Severity,
    /// What kind of problem it is.
    pub code: DiagCode,
    /// Where it is.
    pub location: Location,
    /// Human-readable detail.
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let loc = self.location.to_string();
        if loc.is_empty() {
            write!(f, "{}: [{}] {}", self.severity, self.code, self.message)
        } else {
            write!(
                f,
                "{}: [{}] {} ({loc})",
                self.severity, self.code, self.message
            )
        }
    }
}

/// Bounds and knobs for a verification run. Construct with
/// [`VerifyOpts::default`] and adjust the fields.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct VerifyOpts {
    /// Diagnostics kept in the report. Further findings are counted in
    /// [`VerifyReport::suppressed`] (and per severity) but not stored.
    pub max_diagnostics: usize,
    /// B-tree nodes / directory clusters read, across all structures.
    pub max_nodes: u64,
    /// Records decoded (catalog, extents, attribute, directory entries).
    pub max_records: u64,
    /// Extents (or cluster-chain links) followed.
    pub max_extents: u64,
    /// Memory for the computed allocation map, in bytes. A volume whose
    /// allocation map would need more skips the bitmap cross-check and
    /// reports [`Truncation::Memory`].
    pub max_bitmap_bytes: u64,
}

impl Default for VerifyOpts {
    fn default() -> Self {
        Self {
            max_diagnostics: 1000,
            max_nodes: 1 << 22,
            max_records: 1 << 25,
            max_extents: 1 << 25,
            max_bitmap_bytes: 256 << 20,
        }
    }
}

/// Which bound stopped a walk early.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Truncation {
    /// [`VerifyOpts::max_nodes`] was reached.
    Nodes,
    /// [`VerifyOpts::max_records`] was reached.
    Records,
    /// [`VerifyOpts::max_extents`] was reached.
    Extents,
    /// [`VerifyOpts::max_bitmap_bytes`] was too small for the volume.
    Memory,
}

impl fmt::Display for Truncation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Truncation::Nodes => "node limit reached",
            Truncation::Records => "record limit reached",
            Truncation::Extents => "extent limit reached",
            Truncation::Memory => "allocation-map memory limit reached",
        })
    }
}

/// Counters describing how much a verification run looked at.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyStats {
    /// Nodes / directory clusters read.
    pub nodes: u64,
    /// Records decoded.
    pub records: u64,
    /// Extents / chain links followed.
    pub extents: u64,
    /// Files seen.
    pub files: u64,
    /// Folders / directories seen (including the root).
    pub folders: u64,
    /// Allocation blocks / clusters in the volume.
    pub total_blocks: u64,
    /// Allocation blocks / clusters the bitmap marks free.
    pub free_blocks: u64,
}

/// The result of a verification run.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    /// Which filesystem was checked: `"hfs+"`, `"hfsx"`, `"fat32"`, ….
    pub fs: &'static str,
    /// Findings, in the order they were made, at most
    /// [`VerifyOpts::max_diagnostics`] of them.
    pub diagnostics: Vec<Diagnostic>,
    /// Findings not stored because `max_diagnostics` was reached.
    pub suppressed: u64,
    /// Total errors found, stored or not.
    pub error_count: u64,
    /// Total warnings found, stored or not.
    pub warning_count: u64,
    /// The bounds that cut the walk short, if any. Non-empty means the
    /// report is incomplete.
    pub truncated: Vec<Truncation>,
    /// What was visited.
    pub stats: VerifyStats,
}

impl VerifyReport {
    /// A fresh empty report for `fs`.
    pub fn new(fs: &'static str) -> Self {
        Self {
            fs,
            ..Self::default()
        }
    }

    /// True when every check ran to completion and found no error.
    /// Warnings and informational notes do not make a volume unclean.
    pub fn is_clean(&self) -> bool {
        self.error_count == 0 && self.truncated.is_empty()
    }

    /// True when no bound cut the walk short.
    pub fn is_complete(&self) -> bool {
        self.truncated.is_empty()
    }

    /// The stored errors.
    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
    }

    /// True when a stored diagnostic carries `code`.
    pub fn has(&self, code: DiagCode) -> bool {
        self.diagnostics.iter().any(|d| d.code == code)
    }

    /// Record a truncation (once per kind).
    #[cfg(any(feature = "hfs-plus", feature = "fat"))]
    pub(crate) fn truncate(&mut self, t: Truncation) {
        if !self.truncated.contains(&t) {
            self.truncated.push(t);
        }
    }
}

#[cfg(any(feature = "hfs-plus", feature = "fat"))]
/// Collector the verifiers share: applies `max_diagnostics`, counts by
/// severity, and meters node/record/extent budgets.
pub(crate) struct Collector {
    pub report: VerifyReport,
    pub opts: VerifyOpts,
}

#[cfg(any(feature = "hfs-plus", feature = "fat"))]
impl Collector {
    pub fn new(fs: &'static str, opts: &VerifyOpts) -> Self {
        Self {
            report: VerifyReport::new(fs),
            opts: opts.clone(),
        }
    }

    pub fn push(
        &mut self,
        severity: Severity,
        code: DiagCode,
        location: Location,
        message: impl Into<String>,
    ) {
        match severity {
            Severity::Error => self.report.error_count += 1,
            Severity::Warning => self.report.warning_count += 1,
            Severity::Info => {}
        }
        if self.report.diagnostics.len() >= self.opts.max_diagnostics {
            self.report.suppressed += 1;
            return;
        }
        self.report.diagnostics.push(Diagnostic {
            severity,
            code,
            location,
            message: message.into(),
        });
    }

    pub fn error(&mut self, code: DiagCode, location: Location, message: impl Into<String>) {
        self.push(Severity::Error, code, location, message);
    }

    pub fn warn(&mut self, code: DiagCode, location: Location, message: impl Into<String>) {
        self.push(Severity::Warning, code, location, message);
    }

    pub fn info(&mut self, code: DiagCode, location: Location, message: impl Into<String>) {
        self.push(Severity::Info, code, location, message);
    }

    /// Charge one node; false (and a truncation) once the budget is spent.
    pub fn take_node(&mut self) -> bool {
        if self.report.stats.nodes >= self.opts.max_nodes {
            self.report.truncate(Truncation::Nodes);
            return false;
        }
        self.report.stats.nodes += 1;
        true
    }

    /// Charge one record.
    pub fn take_record(&mut self) -> bool {
        if self.report.stats.records >= self.opts.max_records {
            self.report.truncate(Truncation::Records);
            return false;
        }
        self.report.stats.records += 1;
        true
    }

    /// Charge one extent.
    pub fn take_extent(&mut self) -> bool {
        if self.report.stats.extents >= self.opts.max_extents {
            self.report.truncate(Truncation::Extents);
            return false;
        }
        self.report.stats.extents += 1;
        true
    }

    pub fn finish(self) -> VerifyReport {
        self.report
    }
}

/// Verify whatever supported filesystem `dev` holds (it must start at
/// the volume: slice a partition first).
///
/// Returns [`crate::Error::Unsupported`] when no verifier recognises it.
pub fn verify_volume(
    dev: &mut dyn crate::block::BlockDevice,
    opts: &VerifyOpts,
) -> crate::Result<VerifyReport> {
    #[cfg(feature = "hfs-plus")]
    if crate::fs::hfs_plus::probe(dev)? {
        return crate::fs::hfs_plus::verify::verify(dev, opts);
    }
    #[cfg(feature = "fat")]
    if let Some(r) = crate::fs::fat::verify::probe_and_verify(dev, opts)? {
        return Ok(r);
    }
    let _ = (dev, opts);
    Err(crate::Error::Unsupported(
        "verify: no verifier for this filesystem (supported: HFS+, HFSX, FAT12/16/32)".into(),
    ))
}

#[cfg(any(feature = "hfs-plus", feature = "fat"))]
/// A compact set of block runs, used to report bitmap disagreements as
/// ranges rather than one diagnostic per block.
pub(crate) fn runs_of(mut blocks: impl Iterator<Item = u64>) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    let Some(first) = blocks.next() else {
        return out;
    };
    let (mut s, mut n) = (first, 1u64);
    for b in blocks {
        if b == s + n {
            n += 1;
        } else {
            out.push((s, n));
            s = b;
            n = 1;
        }
    }
    out.push((s, n));
    out
}

#[cfg(all(test, any(feature = "hfs-plus", feature = "fat")))]
mod tests {
    use super::*;

    #[test]
    fn collector_caps_and_counts() {
        let opts = VerifyOpts {
            max_diagnostics: 2,
            ..VerifyOpts::default()
        };
        let mut c = Collector::new("test", &opts);
        for _ in 0..5 {
            c.error(DiagCode::ExtentOverlap, Location::default(), "x");
        }
        c.warn(DiagCode::VolumeDirty, Location::default(), "y");
        let r = c.finish();
        assert_eq!(r.diagnostics.len(), 2);
        assert_eq!(r.suppressed, 4);
        assert_eq!(r.error_count, 5);
        assert_eq!(r.warning_count, 1);
        assert!(!r.is_clean());
    }

    #[test]
    fn budgets_truncate() {
        let opts = VerifyOpts {
            max_nodes: 1,
            ..VerifyOpts::default()
        };
        let mut c = Collector::new("test", &opts);
        assert!(c.take_node());
        assert!(!c.take_node());
        let r = c.finish();
        assert_eq!(r.truncated, vec![Truncation::Nodes]);
        assert!(!r.is_clean());
    }

    #[test]
    fn runs_coalesce() {
        assert_eq!(
            runs_of([1u64, 2, 3, 7, 8, 10].into_iter()),
            vec![(1, 3), (7, 2), (10, 1)]
        );
        assert!(runs_of(std::iter::empty()).is_empty());
    }

    #[test]
    fn display_is_readable() {
        let d = Diagnostic {
            severity: Severity::Error,
            code: DiagCode::BTreeKeyOrder,
            location: Location::structure("catalog").node(5, Some(2)),
            message: "keys out of order".into(),
        };
        assert_eq!(
            d.to_string(),
            "error: [btree-key-order] keys out of order (catalog, node 5, record 2)"
        );
    }
}
