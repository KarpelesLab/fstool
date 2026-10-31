//! The interface between the planner and each filesystem view — the
//! extension point a new view (UDF) plugs into.
//!
//! The planner owns the sector space. A view never picks sectors itself:
//! it says what it needs ([`ViewNeeds`]), the planner assigns them
//! ([`Placement`]), and the view then writes only inside what it was
//! given, pointing its file records at the shared payload extents the
//! planner placed once for every view ([`PayloadLayout`]).
//!
//! The lifecycle of a view, called by [`super::HybridPlan`]:
//!
//! 1. [`HybridView::required_payloads`] — files whose bytes must be
//!    placed even if no view lists them (an El Torito boot image).
//! 2. The planner lays the payloads out (relative offsets), honouring
//!    the largest [`HybridView::payload_alignment`].
//! 3. [`HybridView::prepare`] — the view builds its directory structures
//!    over the entries visible to it, reports what it cannot represent,
//!    and returns its sector needs. Sizes must not depend on where
//!    things end up.
//! 4. The planner assigns every request and validates the whole layout
//!    (no overlaps, nothing out of bounds).
//! 5. [`HybridView::place`] — the view learns its sectors and the
//!    payloads' absolute LBAs, and finalises its structures.
//! 6. [`HybridView::write`] / [`HybridView::verify`] — at write time.

use std::fmt;

use crate::block::BlockDevice;

use super::error::Result;
use super::report::HybridReport;
use super::source::{ContentId, NodeId, SourceKind, SourceTree};

/// Identifies a view (one advertised filesystem) in plans and reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ViewId {
    /// The ISO 9660 primary hierarchy (with Rock Ridge when enabled).
    Iso9660,
    /// The Joliet hierarchy.
    Joliet,
    /// The HFS+ volume.
    HfsPlus,
    /// The UDF volume (feature `udf`).
    Udf,
    /// A caller-supplied view.
    Custom(&'static str),
}

impl fmt::Display for ViewId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Iso9660 => f.write_str("iso9660"),
            Self::Joliet => f.write_str("joliet"),
            Self::HfsPlus => f.write_str("hfs+"),
            Self::Udf => f.write_str("udf"),
            Self::Custom(s) => f.write_str(s),
        }
    }
}

/// A run of 2048-byte sectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Extent {
    /// First sector.
    pub lba: u32,
    /// Number of sectors.
    pub sectors: u32,
}

impl Extent {
    /// `sectors` sectors from `lba`.
    pub fn new(lba: u32, sectors: u32) -> Self {
        Self { lba, sectors }
    }
    /// One past the last sector.
    pub fn end(&self) -> u64 {
        u64::from(self.lba) + u64::from(self.sectors)
    }
}

/// A floating run of sectors the planner may put anywhere in the head
/// (before the payloads) or tail (after them).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SectorRequest {
    /// What it holds (shown in the plan).
    pub label: String,
    /// Length in sectors.
    pub sectors: u32,
    /// Required alignment of its first sector, in sectors (0 or 1: none).
    pub align: u32,
}

impl SectorRequest {
    /// A request for `sectors` unaligned sectors.
    pub fn new(label: impl Into<String>, sectors: u32) -> Self {
        Self {
            label: label.into(),
            sectors,
            align: 1,
        }
    }
}

/// Sectors at a fixed LBA (UDF's anchor at 256). Always before the
/// payloads; the planner keeps them clear of everything else.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FixedRequest {
    /// What it holds.
    pub label: String,
    /// First sector (16 or more).
    pub lba: u32,
    /// Length in sectors.
    pub sectors: u32,
}

impl FixedRequest {
    /// `sectors` sectors at `lba`.
    pub fn new(label: impl Into<String>, lba: u32, sectors: u32) -> Self {
        Self {
            label: label.into(),
            lba,
            sectors,
        }
    }
}

/// Sectors at a fixed distance from the end of the image: the region
/// starts at `total_sectors - from_end` (UDF's anchors at N-1 and N-257).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EndRequest {
    /// What it holds.
    pub label: String,
    /// Distance of the first sector from the end (≥ `sectors`).
    pub from_end: u32,
    /// Length in sectors.
    pub sectors: u32,
}

impl EndRequest {
    /// `sectors` sectors starting `from_end` sectors before the end.
    pub fn new(label: impl Into<String>, from_end: u32, sectors: u32) -> Self {
        Self {
            label: label.into(),
            from_end,
            sectors,
        }
    }
}

/// Bytes in the 32 KiB system area (LBAs 0–15) — partition maps.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ByteRequest {
    /// What it holds.
    pub label: String,
    /// First byte.
    pub offset: u64,
    /// Length in bytes.
    pub len: u64,
}

impl ByteRequest {
    /// `len` bytes at `offset`.
    pub fn new(label: impl Into<String>, offset: u64, len: u64) -> Self {
        Self {
            label: label.into(),
            offset,
            len,
        }
    }
}

/// A view that encloses the payloads in a partition of its own (HFS+):
/// `head_sectors` immediately before the payloads it lists, and
/// `tail_sectors` immediately after them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WrapRequest {
    /// Sectors between the start of the partition and the payloads.
    pub head_sectors: u32,
    /// Sectors between the payloads and the end of the partition.
    pub tail_sectors: u32,
}

impl WrapRequest {
    /// A wrapper with the given head and tail.
    pub fn new(head_sectors: u32, tail_sectors: u32) -> Self {
        Self {
            head_sectors,
            tail_sectors,
        }
    }
}

/// Everything a view asks the planner for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ViewNeeds {
    /// Sectors in the volume recognition area starting at LBA 16, in
    /// view order (ISO 9660's descriptor set first, then UDF's
    /// BEA01/NSR02/TEA01).
    pub vrs_sectors: u32,
    /// Byte claims in the system area.
    pub system_area: Vec<ByteRequest>,
    /// Sectors at fixed LBAs.
    pub fixed: Vec<FixedRequest>,
    /// Floating sectors before the payloads.
    pub head: Vec<SectorRequest>,
    /// Floating sectors after the payloads.
    pub tail: Vec<SectorRequest>,
    /// Sectors relative to the end of the image.
    pub from_end: Vec<EndRequest>,
    /// The payload-enclosing partition, for the (single) wrapper view.
    pub wrap: Option<WrapRequest>,
}

/// Which part of the payload area a content lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PayloadZone {
    /// Inside the wrapper's partition: listed by the wrapper view.
    Wrapped,
    /// After the wrapper's partition: not listed by the wrapper view
    /// (so its blocks are not part of that filesystem at all).
    Outside,
}

/// Where one content's bytes are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PayloadEntry {
    /// The content.
    pub content: ContentId,
    /// Its zone.
    pub zone: PayloadZone,
    /// First sector (relative to the zone during
    /// [`HybridView::prepare`], absolute afterwards).
    pub lba: u32,
    /// Sectors reserved (whole multiples of the payload alignment).
    pub sectors: u32,
    /// Length in bytes.
    pub len: u64,
}

/// Every placed payload. Contents of zero length occupy no sectors and
/// have no entry.
#[derive(Debug, Clone, Default)]
pub struct PayloadLayout {
    pub(crate) entries: Vec<PayloadEntry>,
    pub(crate) by_content: Vec<Option<usize>>,
    pub(crate) wrapped_sectors: u32,
    pub(crate) outside_sectors: u32,
    pub(crate) align: u32,
}

impl PayloadLayout {
    /// All entries, in placement order.
    pub fn entries(&self) -> &[PayloadEntry] {
        &self.entries
    }

    /// The entry of content `c`, if placed.
    pub fn entry(&self, c: ContentId) -> Option<&PayloadEntry> {
        self.by_content
            .get(c)
            .copied()
            .flatten()
            .map(|i| &self.entries[i])
    }

    /// `(lba, len)` of the file at `node`: `Some((0, 0))` for an empty
    /// file, `None` for a non-file or a content that was not placed.
    pub fn extent_of(&self, tree: &SourceTree, node: NodeId) -> Option<(u32, u64)> {
        let SourceKind::File { content } = tree.node(node).kind else {
            return None;
        };
        if tree.content(content).len == 0 {
            return Some((0, 0));
        }
        self.entry(content).map(|e| (e.lba, e.len))
    }

    /// Sectors of the wrapped zone.
    pub fn wrapped_sectors(&self) -> u32 {
        self.wrapped_sectors
    }

    /// Sectors of the outside zone.
    pub fn outside_sectors(&self) -> u32 {
        self.outside_sectors
    }

    /// Alignment of every entry, in sectors.
    pub fn alignment(&self) -> u32 {
        self.align
    }
}

/// Per-view visibility of the tree's nodes.
#[derive(Debug, Clone, Default)]
pub struct Visibility {
    pub(crate) views: Vec<(ViewId, Vec<bool>)>,
}

impl Visibility {
    /// Whether `node` appears in `view` (false for an unknown view).
    pub fn visible(&self, view: ViewId, node: NodeId) -> bool {
        self.views
            .iter()
            .find(|(v, _)| *v == view)
            .map(|(_, m)| m[node])
            .unwrap_or(false)
    }
}

/// What [`HybridView::prepare`] sees.
#[non_exhaustive]
pub struct ViewInput<'a> {
    /// The source tree.
    pub tree: &'a SourceTree,
    /// Which nodes each view shows (after `hide` / `only` globs).
    pub visibility: &'a Visibility,
    /// Payload sizes and relative offsets (absolute LBAs come with
    /// [`Placement`]).
    pub payload: &'a PayloadLayout,
    /// Default volume date, seconds since the Unix epoch.
    pub create_date: i64,
}

/// The wrapper view's partition, absolute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WrapPlacement {
    /// First sector of the partition.
    pub start: u32,
    /// First sector of the wrapped payloads.
    pub payload_start: u32,
    /// One past the last wrapped payload sector.
    pub payload_end: u32,
    /// One past the last sector of the partition.
    pub end: u32,
}

/// The sectors a view was given, in the order it asked for them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ViewPlacement {
    /// Its share of the volume recognition area.
    pub vrs: Extent,
    /// Its system-area byte claims, `(offset, len)`.
    pub system_area: Vec<(u64, u64)>,
    /// Fixed requests.
    pub fixed: Vec<Extent>,
    /// Head requests.
    pub head: Vec<Extent>,
    /// Tail requests.
    pub tail: Vec<Extent>,
    /// End-relative requests.
    pub from_end: Vec<Extent>,
}

/// What [`HybridView::place`], [`HybridView::write`] and
/// [`HybridView::verify`] see.
#[non_exhaustive]
pub struct Placement<'a> {
    /// The source tree.
    pub tree: &'a SourceTree,
    /// Per-view visibility.
    pub visibility: &'a Visibility,
    /// Payloads with absolute LBAs.
    pub payload: &'a PayloadLayout,
    /// Size of the image in sectors.
    pub total_sectors: u32,
    /// This view's sectors.
    pub own: &'a ViewPlacement,
    /// The wrapper's partition, if any view wraps (it may be this one).
    pub wrap: Option<WrapPlacement>,
}

/// One filesystem view of a hybrid image.
///
/// # Adding a view
///
/// Implement this trait in `src/fs/hybrid/<view>.rs` and hand an
/// instance to [`super::HybridPlan::with_views`] (or add it to
/// [`super::build_views`] behind an option, as the ISO 9660 and HFS+ views
/// are). The UDF view (`src/fs/hybrid/udf_view.rs`) does this:
///
/// * return [`ViewId::Udf`] from [`id`](Self::id);
/// * in [`prepare`](Self::prepare), walk the nodes with
///   `input.visibility.visible(ViewId::Udf, n)`, build its file entries
///   and file identifier descriptors over `input.payload` (sizes only —
///   LBAs come later), and ask for `vrs_sectors: 3` (BEA01, NSR02,
///   TEA01 — the planner puts them right after ISO 9660's terminator),
///   a [`FixedRequest`] for the anchor at 256, an [`EndRequest`] for the
///   anchor at N-1, head [`SectorRequest`]s for the main and reserve
///   volume descriptor sequences and the integrity sequence, and a tail
///   one for the metadata (file set descriptor, directories, file
///   entries);
/// * in [`place`](Self::place), choose its partition (the first payload
///   sector through the end of its tail metadata), translate `payload.extent_of(tree, n)` into
///   partition-relative short / long allocation descriptors, and
///   compute descriptor tags and CRCs;
/// * in [`write`](Self::write), write exactly the sectors in `own`;
/// * in [`verify`](Self::verify), read the volume back (tag checksums,
///   CRCs, the tree and every file's extents against `payload`).
///
/// Files of a view that does not wrap may live in either payload zone;
/// a view never writes payload bytes (the planner does, once).
pub trait HybridView {
    /// The view's identity (the first of [`covers`](Self::covers)).
    fn id(&self) -> ViewId;

    /// Every view this object advertises — the ISO 9660 view also
    /// carries the Joliet hierarchy. Visibility is computed per entry.
    fn covers(&self) -> Vec<ViewId> {
        vec![self.id()]
    }

    /// Nodes whose payload must be placed even when no view lists them.
    fn required_payloads(&self, _tree: &SourceTree) -> Result<Vec<NodeId>> {
        Ok(Vec::new())
    }

    /// Alignment of every payload, in sectors (HFS+ with 4 KiB blocks: 2).
    fn payload_alignment(&self) -> u32 {
        1
    }

    /// Whether this view encloses the payloads it lists in a partition
    /// of its own (at most one view may).
    fn wraps_payload(&self) -> bool {
        false
    }

    /// Build the view's structures and say what it needs.
    fn prepare(&mut self, input: &ViewInput<'_>, report: &mut HybridReport) -> Result<ViewNeeds>;

    /// Finalise against absolute positions; return sub-regions worth
    /// showing in the plan (each must lie inside `placement.own`).
    fn place(&mut self, placement: &Placement<'_>) -> Result<Vec<(String, Extent)>>;

    /// Write the view's metadata (never the payloads).
    fn write(&self, dev: &mut dyn BlockDevice, placement: &Placement<'_>) -> Result<()>;

    /// Read the view back with an independent reader and compare it with
    /// the plan.
    fn verify(&self, _dev: &mut dyn BlockDevice, _placement: &Placement<'_>) -> Result<()> {
        Ok(())
    }

    /// Short `(key, value)` facts for the plan summary (labels, sizes).
    fn summary(&self) -> Vec<(String, String)> {
        Vec::new()
    }
}
