//! The planner: one sector space for every view, payloads placed once,
//! every region validated before a byte is written.

use std::fmt;
use std::io::Read;

use crate::block::BlockDevice;

use super::error::{HybridError, Result};
use super::glob::Glob;
use super::report::{HybridReport, OmitReason, ReportKind};
use super::source::{HostPayloads, NodeId, PayloadOpener, SourceKind, SourceTree};
use super::view::{
    Extent, HybridView, PayloadEntry, PayloadLayout, PayloadZone, Placement, ViewId, ViewInput,
    ViewNeeds, ViewPlacement, Visibility, WrapPlacement,
};
use super::{HybridOptions, build_views, filters};

/// Sector size of the image.
pub(crate) const SECTOR: u64 = 2048;
/// First sector after the system area.
const SYSTEM_AREA_SECTORS: u32 = 16;

/// One region of the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlannedRegion {
    /// The view owning it; `None` for the shared payload zones.
    pub view: Option<ViewId>,
    /// What it holds.
    pub label: String,
    /// The sectors.
    pub extent: Extent,
}

/// One file of the plan: where its bytes are and which views list it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlannedFile {
    /// Tree path of the first name of the content.
    pub path: String,
    /// The payload extent (sectors reserved; `len` bytes are used).
    pub extent: Extent,
    /// Payload length in bytes.
    pub len: u64,
    /// Zone of the payload.
    pub zone: PayloadZone,
    /// Views listing at least one name of it.
    pub views: Vec<ViewId>,
}

/// A planned hybrid image: every view's structures sized and placed,
/// every payload assigned its sectors once, the layout validated. Inspect
/// it, then [`write`](Self::write) it.
pub struct HybridPlan {
    tree: SourceTree,
    views: Vec<Box<dyn HybridView>>,
    placements: Vec<ViewPlacement>,
    wrap: Option<WrapPlacement>,
    visibility: Visibility,
    payload: PayloadLayout,
    regions: Vec<PlannedRegion>,
    files: Vec<PlannedFile>,
    total_sectors: u32,
    report: HybridReport,
}

impl fmt::Debug for HybridPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridPlan")
            .field("views", &self.view_ids())
            .field("total_sectors", &self.total_sectors)
            .field("regions", &self.regions)
            .field("files", &self.files.len())
            .field("report", &self.report.items().len())
            .finish()
    }
}

impl HybridPlan {
    /// Plan `tree` with the views `opts` enables.
    pub fn new(tree: SourceTree, opts: &HybridOptions) -> Result<Self> {
        Self::with_views(tree, opts, Vec::new())
    }

    /// Plan `tree` with the built-in views `opts` enables plus `extra`
    /// (planned after them, in order).
    pub fn with_views(
        tree: SourceTree,
        opts: &HybridOptions,
        extra: Vec<Box<dyn HybridView>>,
    ) -> Result<Self> {
        let mut views = build_views(opts);
        views.extend(extra);
        if views.is_empty() {
            return Err(HybridError::NoViews);
        }
        let mut report = HybridReport::default();
        let covered: Vec<ViewId> = views.iter().flat_map(|v| v.covers()).collect();
        let visibility = compute_visibility(&tree, opts, &covered, &mut report);

        // Wrapper.
        let wrappers: Vec<ViewId> = views
            .iter()
            .filter(|v| v.wraps_payload())
            .map(|v| v.id())
            .collect();
        if wrappers.len() > 1 {
            return Err(HybridError::MultipleWrappers(wrappers));
        }
        let wrapper_covers: Vec<ViewId> = views
            .iter()
            .find(|v| v.wraps_payload())
            .map(|v| v.covers())
            .unwrap_or_default();

        // Payloads: every content a visible file refers to, plus those
        // the views require.
        let mut required = Vec::new();
        for v in &views {
            required.extend(v.required_payloads(&tree)?);
        }
        let align = views
            .iter()
            .map(|v| v.payload_alignment().max(1))
            .max()
            .unwrap_or(1);
        let mut payload = layout_payloads(
            &tree,
            &visibility,
            &covered,
            &wrapper_covers,
            &required,
            align,
        )?;

        // Needs.
        let mut needs = Vec::with_capacity(views.len());
        {
            let input = ViewInput {
                tree: &tree,
                visibility: &visibility,
                payload: &payload,
                create_date: opts.create_date,
            };
            for v in views.iter_mut() {
                needs.push(v.prepare(&input, &mut report)?);
            }
        }
        let wrapper_idx = views.iter().position(|v| v.wraps_payload());
        if let Some(w) = wrapper_idx
            && needs[w].wrap.is_none()
        {
            return Err(HybridError::InvalidOption(format!(
                "view {} wraps the payloads but asked for no partition",
                views[w].id()
            )));
        }

        // Assignment.
        let ids: Vec<ViewId> = views.iter().map(|v| v.id()).collect();
        let assigned = assign(&ids, &needs, wrapper_idx, &mut payload)?;

        // Let every view finalise against absolute positions.
        let mut regions = assigned.regions.clone();
        for (i, v) in views.iter_mut().enumerate() {
            let p = Placement {
                tree: &tree,
                visibility: &visibility,
                payload: &payload,
                total_sectors: assigned.total,
                own: &assigned.placements[i],
                wrap: assigned.wrap,
            };
            let subs = v.place(&p)?;
            let own = own_extents(
                &assigned.placements[i],
                assigned.wrap,
                wrapper_idx == Some(i),
            );
            for (label, e) in subs {
                if e.sectors == 0 {
                    continue;
                }
                if !own.iter().any(|o| e.lba >= o.lba && e.end() <= o.end()) {
                    return Err(HybridError::OutOfBounds {
                        region: format!("{}: {label}", ids[i]),
                        range: (u64::from(e.lba), e.end()),
                        limit: u64::from(assigned.total),
                    });
                }
                regions.push(PlannedRegion {
                    view: Some(ids[i]),
                    label,
                    extent: e,
                });
            }
        }
        regions.sort_by_key(|r| (r.extent.lba, r.extent.sectors));

        let links = tree.links_of();
        let mut files = Vec::new();
        for e in &payload.entries {
            let names = &links[e.content];
            let mut vs: Vec<ViewId> = covered
                .iter()
                .copied()
                .filter(|v| names.iter().any(|&n| visibility.visible(*v, n)))
                .collect();
            vs.dedup();
            let path = names.first().map(|&n| tree.path_of(n)).unwrap_or_default();
            files.push(PlannedFile {
                path,
                extent: Extent::new(e.lba, e.sectors),
                len: e.len,
                zone: e.zone,
                views: vs,
            });
        }

        Ok(Self {
            tree,
            views,
            placements: assigned.placements,
            wrap: assigned.wrap,
            visibility,
            payload,
            regions,
            files,
            total_sectors: assigned.total,
            report,
        })
    }

    /// Views advertised, in planning order.
    pub fn view_ids(&self) -> Vec<ViewId> {
        self.views.iter().flat_map(|v| v.covers()).collect()
    }

    /// Image size in sectors.
    pub fn total_sectors(&self) -> u32 {
        self.total_sectors
    }

    /// Image size in bytes.
    pub fn total_bytes(&self) -> u64 {
        u64::from(self.total_sectors) * SECTOR
    }

    /// Every metadata region and payload zone, by LBA.
    pub fn regions(&self) -> &[PlannedRegion] {
        &self.regions
    }

    /// Every placed payload.
    pub fn files(&self) -> &[PlannedFile] {
        &self.files
    }

    /// The payload layout (absolute).
    pub fn payload(&self) -> &PayloadLayout {
        &self.payload
    }

    /// The wrapper partition, when one view wraps the payloads.
    pub fn wrap(&self) -> Option<WrapPlacement> {
        self.wrap
    }

    /// The source tree.
    pub fn tree(&self) -> &SourceTree {
        &self.tree
    }

    /// Per-view visibility.
    pub fn visibility(&self) -> &Visibility {
        &self.visibility
    }

    /// What the views changed or left out.
    pub fn report(&self) -> &HybridReport {
        &self.report
    }

    /// `(view, key, value)` facts from every view (labels, sizes).
    pub fn summary(&self) -> Vec<(ViewId, String, String)> {
        self.views
            .iter()
            .flat_map(|v| {
                let id = v.id();
                v.summary().into_iter().map(move |(k, val)| (id, k, val))
            })
            .collect()
    }

    fn placement(&self, i: usize) -> Placement<'_> {
        Placement {
            tree: &self.tree,
            visibility: &self.visibility,
            payload: &self.payload,
            total_sectors: self.total_sectors,
            own: &self.placements[i],
            wrap: self.wrap,
        }
    }

    /// Write the image to `dev` (which must hold
    /// [`total_bytes`](Self::total_bytes)), reading payloads from host
    /// paths, memory or zeros.
    pub fn write(&self, dev: &mut dyn BlockDevice) -> Result<()> {
        self.write_with(dev, &mut HostPayloads)
    }

    /// Write the image, opening payloads through `opener`. Each payload
    /// is streamed once, 1 MiB at a time, to its sectors; then each view
    /// writes its metadata.
    pub fn write_with(
        &self,
        dev: &mut dyn BlockDevice,
        opener: &mut dyn PayloadOpener,
    ) -> Result<()> {
        let needed = self.total_bytes();
        let available = dev.total_size();
        if available < needed {
            return Err(HybridError::DeviceTooSmall { needed, available });
        }
        // System area and every metadata region start out zeroed; payload
        // sectors are written in full (tail padding included).
        dev.zero_range(0, u64::from(SYSTEM_AREA_SECTORS) * SECTOR)?;
        for r in &self.regions {
            if r.view.is_some() {
                dev.zero_range(
                    u64::from(r.extent.lba) * SECTOR,
                    u64::from(r.extent.sectors) * SECTOR,
                )?;
            }
        }
        let links = self.tree.links_of();
        let mut buf = vec![0u8; 1 << 20];
        for e in &self.payload.entries {
            let content = self.tree.content(e.content);
            let path = links[e.content]
                .first()
                .map(|&n| self.tree.path_of(n))
                .unwrap_or_default();
            copy_payload(dev, opener, &content.payload, e, &path, &mut buf)?;
        }
        for i in 0..self.views.len() {
            let p = self.placement(i);
            self.views[i].write(dev, &p)?;
        }
        Ok(())
    }

    /// Re-read every view with an independent reader and compare it with
    /// the plan: descriptor signatures and checksums, the tree each view
    /// lists, and every file's extent.
    pub fn verify(&self, dev: &mut dyn BlockDevice) -> Result<()> {
        for i in 0..self.views.len() {
            let p = self.placement(i);
            self.views[i].verify(dev, &p)?;
        }
        Ok(())
    }
}

fn copy_payload(
    dev: &mut dyn BlockDevice,
    opener: &mut dyn PayloadOpener,
    payload: &super::source::Payload,
    e: &PayloadEntry,
    path: &str,
    buf: &mut [u8],
) -> Result<()> {
    let base = u64::from(e.lba) * SECTOR;
    let span = u64::from(e.sectors) * SECTOR;
    if matches!(payload, super::source::Payload::Zero) {
        dev.zero_range(base, span)?;
        return Ok(());
    }
    let mut r = opener.open(payload)?;
    let mut done = 0u64;
    while done < e.len {
        let want = (e.len - done).min(buf.len() as u64) as usize;
        let n = r.read(&mut buf[..want])?;
        if n == 0 {
            return Err(HybridError::PayloadLength {
                path: path.to_string(),
                expected: e.len,
                actual: done,
            });
        }
        dev.write_at(base + done, &buf[..n])?;
        done += n as u64;
    }
    let mut probe = [0u8; 1];
    if r.read(&mut probe)? != 0 {
        return Err(HybridError::PayloadLength {
            path: path.to_string(),
            expected: e.len,
            actual: e.len + 1,
        });
    }
    if span > e.len {
        dev.zero_range(base + e.len, span - e.len)?;
    }
    Ok(())
}

/// Per-view visibility from the `hide` / `only` globs. A hidden
/// directory hides its subtree; each hide is reported once, at its top.
fn compute_visibility(
    tree: &SourceTree,
    opts: &HybridOptions,
    covered: &[ViewId],
    report: &mut HybridReport,
) -> Visibility {
    let compiled: Vec<(ViewId, Vec<Glob>, Vec<Glob>)> = filters(opts)
        .into_iter()
        .map(|(v, h, o)| {
            (
                v,
                h.iter().map(|g| Glob::new(g)).collect(),
                o.iter().map(|g| Glob::new(g)).collect(),
            )
        })
        .collect();
    let order = tree.preorder();
    let mut out = Visibility::default();
    for &view in covered {
        let mut vis = vec![true; tree.len()];
        for &n in &order {
            if n == SourceTree::ROOT {
                continue;
            }
            let parent = tree.node(n).parent;
            if !vis[parent] {
                vis[n] = false;
                continue;
            }
            let path = tree.path_of(n);
            let rel = path.trim_start_matches('/');
            let name = tree.node(n).name.as_str();
            let mut hit: Option<String> = None;
            for (v, hide, only) in &compiled {
                if *v == view {
                    if let Some(g) = hide.iter().find(|g| g.matches(rel, name)) {
                        hit = Some(g.text().to_string());
                        break;
                    }
                } else if covered.contains(v)
                    && let Some(g) = only.iter().find(|g| g.matches(rel, name))
                {
                    hit = Some(g.text().to_string());
                    break;
                }
            }
            if let Some(pattern) = hit {
                vis[n] = false;
                report.push(
                    view,
                    path,
                    ReportKind::Omitted(OmitReason::Hidden { pattern }),
                );
            }
        }
        out.views.push((view, vis));
    }
    out
}

fn layout_payloads(
    tree: &SourceTree,
    visibility: &Visibility,
    covered: &[ViewId],
    wrapper_covers: &[ViewId],
    required: &[NodeId],
    align: u32,
) -> Result<PayloadLayout> {
    let links = tree.links_of();
    let mut order: Vec<usize> = Vec::new();
    let mut seen = vec![false; tree.content_count()];
    let mut push = |c: usize, order: &mut Vec<usize>| {
        if !seen[c] {
            seen[c] = true;
            order.push(c);
        }
    };
    for &n in required {
        if let SourceKind::File { content } = tree.node(n).kind {
            push(content, &mut order);
        }
    }
    for n in tree.preorder() {
        if let SourceKind::File { content } = tree.node(n).kind
            && covered.iter().any(|v| visibility.visible(*v, n))
        {
            push(content, &mut order);
        }
    }
    let unit = u64::from(align) * SECTOR;
    let mut layout = PayloadLayout {
        by_content: vec![None; tree.content_count()],
        align,
        ..PayloadLayout::default()
    };
    let mut wrapped: u64 = 0;
    let mut outside: u64 = 0;
    for c in order {
        let len = tree.content(c).len;
        if len == 0 {
            continue;
        }
        let in_wrapper = links[c]
            .iter()
            .any(|&n| wrapper_covers.iter().any(|v| visibility.visible(*v, n)));
        let sectors = len.div_ceil(unit) * u64::from(align);
        let sectors_u32 = u32::try_from(sectors).map_err(|_| HybridError::TooLarge {
            what: format!("file {}", tree.path_of(links[c][0])),
            size: len,
            limit: u64::from(u32::MAX) * SECTOR,
        })?;
        let zone = if in_wrapper {
            PayloadZone::Wrapped
        } else {
            PayloadZone::Outside
        };
        let cursor = if in_wrapper {
            &mut wrapped
        } else {
            &mut outside
        };
        let lba = u32::try_from(*cursor).map_err(|_| too_big(*cursor))?;
        *cursor += sectors;
        layout.by_content[c] = Some(layout.entries.len());
        layout.entries.push(PayloadEntry {
            content: c,
            zone,
            lba,
            sectors: sectors_u32,
            len,
        });
    }
    layout.wrapped_sectors = u32::try_from(wrapped).map_err(|_| too_big(wrapped))?;
    layout.outside_sectors = u32::try_from(outside).map_err(|_| too_big(outside))?;
    Ok(layout)
}

fn too_big(sectors: u64) -> HybridError {
    HybridError::TooLarge {
        what: "image".into(),
        size: sectors * SECTOR,
        limit: u64::from(u32::MAX) * SECTOR,
    }
}

struct Assigned {
    placements: Vec<ViewPlacement>,
    wrap: Option<WrapPlacement>,
    regions: Vec<PlannedRegion>,
    total: u32,
}

fn own_extents(p: &ViewPlacement, wrap: Option<WrapPlacement>, wrapper: bool) -> Vec<Extent> {
    let mut v = vec![p.vrs];
    v.extend(p.fixed.iter().copied());
    v.extend(p.head.iter().copied());
    v.extend(p.tail.iter().copied());
    v.extend(p.from_end.iter().copied());
    if wrapper && let Some(w) = wrap {
        v.push(Extent::new(w.start, w.end - w.start));
    }
    v
}

fn align_up(x: u64, a: u32) -> u64 {
    let a = u64::from(a.max(1));
    x.div_ceil(a) * a
}

/// Assign every request a place and validate the result.
fn assign(
    ids: &[ViewId],
    needs: &[ViewNeeds],
    wrapper: Option<usize>,
    payload: &mut PayloadLayout,
) -> Result<Assigned> {
    let mut placements = vec![ViewPlacement::default(); needs.len()];
    let mut regions: Vec<PlannedRegion> = Vec::new();
    let region =
        |view: Option<ViewId>, label: &str, lba: u64, sectors: u32| -> Result<PlannedRegion> {
            Ok(PlannedRegion {
                view,
                label: label.to_string(),
                extent: Extent::new(u32::try_from(lba).map_err(|_| too_big(lba))?, sectors),
            })
        };

    // System area: byte claims inside LBAs 0..16, pairwise disjoint.
    let mut bytes: Vec<(String, u64, u64)> = Vec::new();
    for (i, n) in needs.iter().enumerate() {
        for b in &n.system_area {
            let end = b.offset.saturating_add(b.len);
            let label = format!("{}: {}", ids[i], b.label);
            if end > u64::from(SYSTEM_AREA_SECTORS) * SECTOR {
                return Err(HybridError::OutOfBounds {
                    region: label,
                    range: (b.offset, end),
                    limit: u64::from(SYSTEM_AREA_SECTORS) * SECTOR,
                });
            }
            bytes.push((label, b.offset, end));
            placements[i].system_area.push((b.offset, b.len));
        }
    }
    check_disjoint(&bytes)?;

    // Volume recognition area, in view order from LBA 16.
    let mut cursor = u64::from(SYSTEM_AREA_SECTORS);
    for (i, n) in needs.iter().enumerate() {
        placements[i].vrs = Extent::new(cursor as u32, n.vrs_sectors);
        if n.vrs_sectors > 0 {
            regions.push(region(
                Some(ids[i]),
                "volume recognition",
                cursor,
                n.vrs_sectors,
            )?);
        }
        cursor += u64::from(n.vrs_sectors);
    }

    // Fixed claims.
    let mut fixed: Vec<(u64, u64)> = Vec::new();
    for (i, n) in needs.iter().enumerate() {
        for f in &n.fixed {
            let start = u64::from(f.lba);
            if start < u64::from(SYSTEM_AREA_SECTORS) {
                return Err(HybridError::OutOfBounds {
                    region: format!("{}: {}", ids[i], f.label),
                    range: (start, start + u64::from(f.sectors)),
                    limit: u64::from(SYSTEM_AREA_SECTORS),
                });
            }
            placements[i].fixed.push(Extent::new(f.lba, f.sectors));
            regions.push(region(Some(ids[i]), &f.label, start, f.sectors)?);
            fixed.push((start, start + u64::from(f.sectors)));
        }
    }
    fixed.sort();

    // Floating head requests, around the fixed claims.
    for (i, n) in needs.iter().enumerate() {
        for h in &n.head {
            if h.sectors == 0 {
                placements[i].head.push(Extent::new(cursor as u32, 0));
                continue;
            }
            let mut at = align_up(cursor, h.align);
            while let Some(&(_, fe)) = fixed
                .iter()
                .find(|&&(fs, fe)| at < fe && at + u64::from(h.sectors) > fs)
            {
                at = align_up(fe, h.align);
            }
            placements[i].head.push(Extent::new(
                u32::try_from(at).map_err(|_| too_big(at))?,
                h.sectors,
            ));
            regions.push(region(Some(ids[i]), &h.label, at, h.sectors)?);
            cursor = cursor.max(at + u64::from(h.sectors));
        }
    }
    if let Some(&(_, fe)) = fixed.last() {
        cursor = cursor.max(fe);
    }

    // The wrapper partition around the wrapped payloads.
    let mut wrap = None;
    let wrapped_base;
    match wrapper {
        Some(w) => {
            let req = needs[w].wrap.expect("checked by the caller");
            let start = cursor;
            wrapped_base = start + u64::from(req.head_sectors);
            let payload_end = wrapped_base + u64::from(payload.wrapped_sectors);
            let end = payload_end + u64::from(req.tail_sectors);
            for x in [start, wrapped_base, payload_end, end] {
                u32::try_from(x).map_err(|_| too_big(x))?;
            }
            wrap = Some(WrapPlacement {
                start: start as u32,
                payload_start: wrapped_base as u32,
                payload_end: payload_end as u32,
                end: end as u32,
            });
            regions.push(region(
                Some(ids[w]),
                "partition head",
                start,
                req.head_sectors,
            )?);
            if req.tail_sectors > 0 {
                regions.push(region(
                    Some(ids[w]),
                    "partition tail",
                    payload_end,
                    req.tail_sectors,
                )?);
            }
            cursor = end;
        }
        None => {
            if payload.wrapped_sectors != 0 {
                return Err(HybridError::InvalidOption(
                    "payloads were assigned to a wrapper partition but no view wraps".into(),
                ));
            }
            wrapped_base = cursor;
        }
    }
    if payload.wrapped_sectors > 0 {
        regions.push(region(
            None,
            "payload (in partition)",
            wrapped_base,
            payload.wrapped_sectors,
        )?);
    }
    let outside_base = align_up(cursor, payload.align);
    if payload.outside_sectors > 0 {
        regions.push(region(
            None,
            "payload (outside partition)",
            outside_base,
            payload.outside_sectors,
        )?);
    }
    cursor = outside_base + u64::from(payload.outside_sectors);
    for e in &mut payload.entries {
        let base = match e.zone {
            PayloadZone::Wrapped => wrapped_base,
            PayloadZone::Outside => outside_base,
        };
        let lba = base + u64::from(e.lba);
        e.lba = u32::try_from(lba).map_err(|_| too_big(lba))?;
    }

    // Floating tail requests.
    for (i, n) in needs.iter().enumerate() {
        for t in &n.tail {
            let at = align_up(cursor, t.align);
            placements[i].tail.push(Extent::new(
                u32::try_from(at).map_err(|_| too_big(at))?,
                t.sectors,
            ));
            if t.sectors > 0 {
                regions.push(region(Some(ids[i]), &t.label, at, t.sectors)?);
            }
            cursor = at + u64::from(t.sectors);
        }
    }

    // End-relative claims.
    let reserve = needs
        .iter()
        .flat_map(|n| n.from_end.iter().map(|e| u64::from(e.from_end)))
        .max()
        .unwrap_or(0);
    let total = cursor + reserve;
    let total32 = u32::try_from(total).map_err(|_| too_big(total))?;
    for (i, n) in needs.iter().enumerate() {
        for e in &n.from_end {
            if e.sectors > e.from_end {
                return Err(HybridError::OutOfBounds {
                    region: format!("{}: {}", ids[i], e.label),
                    range: (
                        total - u64::from(e.from_end),
                        total - u64::from(e.from_end) + u64::from(e.sectors),
                    ),
                    limit: total,
                });
            }
            let lba = total - u64::from(e.from_end);
            placements[i]
                .from_end
                .push(Extent::new(lba as u32, e.sectors));
            regions.push(region(Some(ids[i]), &e.label, lba, e.sectors)?);
        }
    }

    // Global validation: within the image, pairwise disjoint.
    let mut spans: Vec<(String, u64, u64)> = Vec::new();
    for r in &regions {
        if r.extent.sectors == 0 {
            continue;
        }
        let label = match r.view {
            Some(v) => format!("{v}: {}", r.label),
            None => r.label.clone(),
        };
        if r.extent.end() > total {
            return Err(HybridError::OutOfBounds {
                region: label,
                range: (u64::from(r.extent.lba), r.extent.end()),
                limit: total,
            });
        }
        spans.push((label, u64::from(r.extent.lba), r.extent.end()));
    }
    check_disjoint(&spans)?;
    Ok(Assigned {
        placements,
        wrap,
        regions,
        total: total32,
    })
}

fn check_disjoint(spans: &[(String, u64, u64)]) -> Result<()> {
    let mut v: Vec<&(String, u64, u64)> = spans.iter().filter(|s| s.2 > s.1).collect();
    v.sort_by_key(|s| (s.1, s.2));
    for w in v.windows(2) {
        if w[1].1 < w[0].2 {
            return Err(HybridError::Overlap {
                first: w[0].0.clone(),
                first_range: (w[0].1, w[0].2),
                second: w[1].0.clone(),
                second_range: (w[1].1, w[1].2),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn assign_for_test(
    ids: &[ViewId],
    needs: &[ViewNeeds],
    wrapper: Option<usize>,
    payload: &mut PayloadLayout,
) -> Result<(Vec<PlannedRegion>, u32)> {
    assign(ids, needs, wrapper, payload).map(|a| (a.regions, a.total))
}
