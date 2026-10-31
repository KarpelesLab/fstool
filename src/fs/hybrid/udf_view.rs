//! The UDF view: a UDF volume whose File Entries point at the payload
//! sectors the ISO 9660 and HFS+ records also name.
//!
//! Like `hdiutil makehybrid -udf`, the view adds its recognition
//! sequence (`BEA01`, `NSR0x`, `TEA01`) right after the ISO 9660
//! terminator, its two volume descriptor sequences and the integrity
//! sequence ahead of the payloads, an anchor at sector 256 and one in
//! the image's last sector. Its one physical partition starts at the
//! first payload sector and ends after its own metadata (File Set
//! Descriptor, File Entries, directories — and for UDF 2.50 the metadata
//! file and its mirror), which the planner places after the payloads:
//!
//! ```text
//! 16..        ISO 9660 descriptors, terminator, BEA01 NSR0x TEA01
//! ...         ISO 9660 / Joliet metadata; UDF main + reserve VDS, LVID
//! 256         UDF anchor
//! P           ┌ HFS+ partition head
//! S           │ payloads (shared)                 ┐
//!             └ HFS+ alternate volume header      │ UDF partition
//! ...         payloads outside the HFS+ partition │ (read-only)
//! ...         UDF metadata                        ┘
//! N-1         UDF anchor
//! ```
//!
//! The partition is read-only (access type 1, as on pressed media), so
//! the other views' structures inside it are simply unallocated space to
//! UDF; nothing is recorded as free.

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::block::BlockDevice;
use crate::fs::udf::layout::{BlockRange, FileData, UdfImage, UdfPlacement, UdfTree};
use crate::fs::udf::{AccessType, FormatOpts, Udf};
use crate::fs::{DeviceKind, EntryKind, FileMeta, Filesystem};

use super::error::{HybridError, Result};
use super::plan::SECTOR;
use super::report::{HybridReport, ReportKind};
use super::source::{EntryMeta, NodeId, SourceKind, SourceTree};
use super::view::{
    EndRequest, Extent, FixedRequest, HybridView, Placement, SectorRequest, ViewId, ViewInput,
    ViewNeeds,
};
use super::{HybridOptions, UdfOptions};

/// Sectors of each volume descriptor sequence extent (ECMA-167 3/8.4.2
/// asks for at least 16).
const VDS_SECTORS: u32 = 16;
/// Sectors of the integrity sequence (LVID + terminator).
const INTEGRITY_SECTORS: u32 = 2;
/// The fixed anchor.
const ANCHOR_LBA: u32 = 256;
/// Encoded (OSTA CS0) length limit of a file identifier.
const MAX_NAME_BYTES: usize = 255;

#[derive(Debug, Clone)]
enum Op {
    Dir { path: String, node: NodeId },
    File { path: String, node: NodeId },
    Link { path: String, target: String },
    Symlink { path: String, node: NodeId },
    Device { path: String, node: NodeId },
}

impl Op {
    fn path(&self) -> &str {
        match self {
            Op::Dir { path, .. }
            | Op::File { path, .. }
            | Op::Link { path, .. }
            | Op::Symlink { path, .. }
            | Op::Device { path, .. } => path,
        }
    }
}

/// The UDF view. Built by [`super::build_views`] from
/// [`HybridOptions::udf`].
pub struct UdfView {
    opts: UdfOptions,
    label: String,
    create_date: i64,
    format: FormatOpts,
    ops: Vec<Op>,
    metadata_sectors: u32,
    image: Option<UdfImage>,
    partition: BlockRange,
}

impl UdfView {
    /// The view `opts` describes.
    pub fn new(opts: &HybridOptions) -> Self {
        Self {
            opts: opts.udf.clone(),
            label: opts
                .udf
                .volume_name
                .clone()
                .unwrap_or_else(|| opts.volume_name.clone()),
            create_date: opts.create_date,
            format: FormatOpts::default(),
            ops: Vec::new(),
            metadata_sectors: 0,
            image: None,
            partition: BlockRange::default(),
        }
    }

    /// The UDF tree over `payload` (relative LBAs during prepare,
    /// absolute ones afterwards — only sizes matter to the former).
    fn udf_tree(&self, tree: &SourceTree, payload: &super::view::PayloadLayout) -> Result<UdfTree> {
        let mut t = UdfTree::new();
        t.add_dir("/", file_meta(&tree.node(SourceTree::ROOT).meta))?;
        for op in &self.ops {
            match op {
                Op::Dir { path, node } => t.add_dir(path, file_meta(&tree.node(*node).meta))?,
                Op::File { path, node } => {
                    let data = match payload.extent_of(tree, *node) {
                        Some((_, 0)) => FileData::empty(),
                        Some((lba, len)) => FileData::contiguous(u64::from(lba), len),
                        None => {
                            return Err(HybridError::InvalidTree(format!(
                                "{}: no payload placed for a file the UDF view lists",
                                tree.path_of(*node)
                            )));
                        }
                    };
                    t.add_file(path, data, file_meta(&tree.node(*node).meta))?;
                }
                Op::Link { path, target } => t.add_hardlink(path, target)?,
                Op::Symlink { path, node } => {
                    let n = tree.node(*node);
                    let SourceKind::Symlink { target } = &n.kind else {
                        unreachable!("planned as a symlink");
                    };
                    t.add_symlink(path, target, file_meta(&n.meta))?;
                }
                Op::Device { path, node } => {
                    let n = tree.node(*node);
                    let SourceKind::Device { kind, major, minor } = n.kind else {
                        unreachable!("planned as a device");
                    };
                    t.add_device(path, kind, major, minor, file_meta(&n.meta))?;
                }
            }
        }
        Ok(t)
    }
}

fn clamp_time(t: i64) -> u32 {
    t.clamp(0, i64::from(u32::MAX)) as u32
}

fn file_meta(m: &EntryMeta) -> FileMeta {
    let mut f = FileMeta::with_mode(m.mode & 0o7777);
    f.uid = m.uid;
    f.gid = m.gid;
    f.mtime = clamp_time(m.mtime);
    f.atime = clamp_time(m.atime);
    f.ctime = clamp_time(m.ctime);
    f
}

fn cs0_len(s: &str) -> usize {
    crate::fs::udf::ecma::encode_cs0(s).len()
}

/// The longest prefix of `s` whose CS0 form is at most `max` bytes.
fn fit(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        out.push(c);
        if cs0_len(&out) > max {
            out.pop();
            break;
        }
    }
    out
}

/// Per-directory UDF file identifiers: at most 255 bytes of OSTA CS0,
/// no NUL, unique in the directory.
#[derive(Default)]
struct UdfNamer {
    taken: HashSet<String>,
}

impl UdfNamer {
    /// `(name, changed, truncated)`.
    fn map(&mut self, name: &str) -> (String, bool, bool) {
        let clean: String = name
            .chars()
            .map(|c| if c == '\0' { '_' } else { c })
            .collect();
        let mut changed = clean != name;
        if cs0_len(&clean) <= MAX_NAME_BYTES && !self.taken.contains(&clean) {
            self.taken.insert(clean.clone());
            return (clean, changed, false);
        }
        let truncated = cs0_len(&clean) > MAX_NAME_BYTES;
        changed = true;
        let (base, ext) = match clean.rfind('.') {
            Some(i) if i > 0 && clean.len() - i <= 32 => (&clean[..i], &clean[i..]),
            _ => (clean.as_str(), ""),
        };
        for n in 0u32.. {
            let suffix = if n == 0 {
                String::new()
            } else {
                format!("~{n}")
            };
            let mut b: Vec<char> = base.chars().collect();
            let cand = loop {
                let c: String = b.iter().collect::<String>() + &suffix + ext;
                if cs0_len(&c) <= MAX_NAME_BYTES || b.is_empty() {
                    break c;
                }
                b.pop();
            };
            if cs0_len(&cand) <= MAX_NAME_BYTES && !self.taken.contains(&cand) {
                self.taken.insert(cand.clone());
                return (cand, changed, truncated);
            }
        }
        unreachable!("a free suffix exists")
    }
}

impl HybridView for UdfView {
    fn id(&self) -> ViewId {
        ViewId::Udf
    }

    fn prepare(&mut self, input: &ViewInput<'_>, report: &mut HybridReport) -> Result<ViewNeeds> {
        let tree = input.tree;
        let label_of = |s: &str, max: usize, report: &mut HybridReport| -> String {
            let f = fit(s, max);
            if f != s {
                report.push(
                    ViewId::Udf,
                    "/",
                    ReportKind::LabelMapped {
                        from: s.to_string(),
                        to: f.clone(),
                    },
                );
            }
            f
        };
        // Logical volume identifier: the label macOS, Windows and Linux
        // show (126 Latin-1 / 63 UTF-16 characters).
        let lv = label_of(&self.label, 127, report);
        // Primary volume identifier and file set identifier: 30 / 15.
        let vol = match &self.opts.volume_id {
            Some(v) => label_of(v, 31, report),
            None => fit(&lv, 31),
        };
        let fs_id = match &self.opts.file_set_id {
            Some(v) => label_of(v, 31, report),
            None => fit(&lv, 31),
        };
        let fo = FormatOpts {
            revision: self.opts.revision,
            block_size: SECTOR as u32,
            volume_id: vol,
            logical_volume_id: Some(lv),
            file_set_id: Some(fs_id),
            volume_set_id: self.opts.volume_set_id.clone(),
            application_id: self.opts.application_id.clone(),
            recording_time: clamp_time(input.create_date.max(self.create_date)),
            access: AccessType::ReadOnly,
            sparse: false,
            ..FormatOpts::default()
        };
        fo.validate()
            .map_err(|e| HybridError::InvalidOption(format!("UDF: {e}")))?;

        // Walk the visible tree, mapping names per directory.
        self.ops.clear();
        let mut first_link: BTreeMap<usize, String> = BTreeMap::new();
        let mut stack: Vec<(NodeId, String)> = vec![(SourceTree::ROOT, String::new())];
        let mut times_clamped = false;
        let check_times = |m: &EntryMeta, clamped: &mut bool| {
            for t in [m.mtime, m.atime, m.ctime] {
                if t < 0 || t > i64::from(u32::MAX) {
                    *clamped = true;
                }
            }
        };
        check_times(&tree.node(SourceTree::ROOT).meta, &mut times_clamped);
        if !tree.node(SourceTree::ROOT).xattrs.is_empty() {
            report.push(
                ViewId::Udf,
                "/",
                ReportKind::MetadataDropped { what: "xattrs" },
            );
        }
        while let Some((src, dir)) = stack.pop() {
            let mut namer = UdfNamer::default();
            let mut todo = Vec::new();
            for &c in tree.children(src) {
                if !input.visibility.visible(ViewId::Udf, c) {
                    continue;
                }
                let node = tree.node(c);
                let (name, changed, truncated) = namer.map(&node.name);
                if changed {
                    let kind = if truncated {
                        ReportKind::NameTruncated {
                            from: node.name.clone(),
                            to: name.clone(),
                        }
                    } else {
                        ReportKind::NameMapped {
                            from: node.name.clone(),
                            to: name.clone(),
                        }
                    };
                    report.push(ViewId::Udf, tree.path_of(c), kind);
                }
                let path = format!("{dir}/{name}");
                check_times(&node.meta, &mut times_clamped);
                if !node.xattrs.is_empty() {
                    report.push(
                        ViewId::Udf,
                        tree.path_of(c),
                        ReportKind::MetadataDropped { what: "xattrs" },
                    );
                }
                match &node.kind {
                    SourceKind::Dir => {
                        self.ops.push(Op::Dir {
                            path: path.clone(),
                            node: c,
                        });
                        todo.push((c, path));
                    }
                    SourceKind::File { content } => {
                        if let Some(target) = first_link.get(content) {
                            self.ops.push(Op::Link {
                                path,
                                target: target.clone(),
                            });
                        } else {
                            first_link.insert(*content, path.clone());
                            self.ops.push(Op::File { path, node: c });
                        }
                    }
                    SourceKind::Symlink { .. } => self.ops.push(Op::Symlink { path, node: c }),
                    SourceKind::Device { .. } => self.ops.push(Op::Device { path, node: c }),
                }
            }
            for t in todo.into_iter().rev() {
                stack.push(t);
            }
        }
        if times_clamped {
            report.push(
                ViewId::Udf,
                "/",
                ReportKind::MetadataDropped {
                    what: "timestamps outside 1970-2106 (clamped)",
                },
            );
        }

        // Sizes only: the payload positions are still relative, which
        // the requirements do not depend on (read-only: no space bitmap).
        let utree = self.udf_tree(tree, input.payload)?;
        let req = UdfImage::requirements(&utree, &fo, 0)?;
        self.metadata_sectors =
            u32::try_from(req.metadata_blocks).map_err(|_| HybridError::TooLarge {
                what: "UDF metadata (sectors)".into(),
                size: req.metadata_blocks,
                limit: u64::from(u32::MAX),
            })?;
        self.format = fo;

        let mut needs = ViewNeeds {
            vrs_sectors: 3,
            ..ViewNeeds::default()
        };
        needs
            .fixed
            .push(FixedRequest::new("udf anchor", ANCHOR_LBA, 1));
        needs
            .head
            .push(SectorRequest::new("udf main VDS", VDS_SECTORS));
        needs
            .head
            .push(SectorRequest::new("udf reserve VDS", VDS_SECTORS));
        needs.head.push(SectorRequest::new(
            "udf integrity sequence",
            INTEGRITY_SECTORS,
        ));
        needs
            .tail
            .push(SectorRequest::new("udf metadata", self.metadata_sectors));
        needs.from_end.push(EndRequest::new("udf anchor", 1, 1));
        Ok(needs)
    }

    fn place(&mut self, p: &Placement<'_>) -> Result<Vec<(String, Extent)>> {
        let own = p.own;
        let bad =
            || HybridError::InvalidTree("UDF view placed with other requests than it made".into());
        if own.vrs.sectors != 3
            || own.fixed.len() != 1
            || own.head.len() != 3
            || own.tail.len() != 1
            || own.from_end.len() != 1
        {
            return Err(bad());
        }
        let meta = own.tail[0];
        if meta.sectors != self.metadata_sectors {
            return Err(bad());
        }
        // The partition: the first payload sector through the end of the
        // UDF metadata. Everything before it (ISO 9660 metadata, the
        // descriptor sequences, the anchor at 256) stays outside.
        let start = p
            .payload
            .entries()
            .iter()
            .map(|e| e.lba)
            .min()
            .unwrap_or(meta.lba)
            .min(meta.lba);
        let part = BlockRange::new(u64::from(start), meta.end() - u64::from(start));
        let r = |e: Extent| BlockRange::new(u64::from(e.lba), u64::from(e.sectors));
        let mut placement = UdfPlacement::new(SECTOR as u32, u64::from(p.total_sectors), part);
        placement.vrs_offset = u64::from(own.vrs.lba) * SECTOR;
        placement.main_vds = r(own.head[0]);
        placement.reserve_vds = r(own.head[1]);
        placement.integrity = r(own.head[2]);
        placement.anchors = vec![u64::from(own.fixed[0].lba), u64::from(own.from_end[0].lba)];
        placement.free = vec![r(meta)];
        let utree = self.udf_tree(p.tree, p.payload)?;
        let image = UdfImage::build(&utree, &self.format, &placement)?;

        // Every block UDF writes must be one the planner gave it.
        let mut owned: Vec<Extent> = vec![own.vrs];
        owned.extend(own.fixed.iter().copied());
        owned.extend(own.head.iter().copied());
        owned.extend(own.tail.iter().copied());
        owned.extend(own.from_end.iter().copied());
        let mut subs: Vec<(String, Extent)> = Vec::new();
        for u in image.used_ranges() {
            let inside = owned
                .iter()
                .any(|o| u.start >= u64::from(o.lba) && u.start + u.len <= o.end());
            if !inside {
                return Err(HybridError::OutOfBounds {
                    region: format!("udf: {}", u.what),
                    range: (u.start, u.start + u.len),
                    limit: u64::from(p.total_sectors),
                });
            }
            // Only the 2.50 metadata files are worth a line of their own.
            if u.what.starts_with("metadata ") {
                subs.push((
                    format!("udf {}", u.what),
                    Extent::new(u.start as u32, u.len as u32),
                ));
            }
        }
        self.partition = part;
        self.image = Some(image);
        Ok(subs)
    }

    fn write(&self, dev: &mut dyn BlockDevice, _p: &Placement<'_>) -> Result<()> {
        let image = self.image.as_ref().ok_or_else(|| {
            HybridError::InvalidOption("UDF view written before placement".into())
        })?;
        image.write(dev)?;
        Ok(())
    }

    fn verify(&self, dev: &mut dyn BlockDevice, p: &Placement<'_>) -> Result<()> {
        let fail = |detail: String| HybridError::Verify {
            view: ViewId::Udf,
            detail,
        };
        let tree = p.tree;
        let mut udf = Udf::open(dev).map_err(|e| fail(e.to_string()))?;
        {
            let info = udf
                .info()
                .ok_or_else(|| fail("no volume information".into()))?;
            let want = self.format.logical_volume_id();
            if info.logical_volume_id != want {
                return Err(fail(format!(
                    "label is {:?}, planned {want:?}",
                    info.logical_volume_id
                )));
            }
        }
        let mut seen = BTreeMap::new();
        walk(&mut udf, dev, "", &mut seen).map_err(|e| fail(e.to_string()))?;
        let mut expect: BTreeMap<String, (EntryKind, NodeId)> = BTreeMap::new();
        let mut by_path: BTreeMap<&str, NodeId> = BTreeMap::new();
        for op in &self.ops {
            let (kind, node) = match op {
                Op::Dir { node, .. } => (EntryKind::Dir, *node),
                Op::File { node, .. } => (EntryKind::Regular, *node),
                Op::Link { target, .. } => (EntryKind::Regular, by_path[target.as_str()]),
                Op::Symlink { node, .. } => (EntryKind::Symlink, *node),
                Op::Device { node, .. } => (
                    match tree.node(*node).kind {
                        SourceKind::Device {
                            kind: DeviceKind::Char,
                            ..
                        } => EntryKind::Char,
                        SourceKind::Device {
                            kind: DeviceKind::Block,
                            ..
                        } => EntryKind::Block,
                        SourceKind::Device {
                            kind: DeviceKind::Fifo,
                            ..
                        } => EntryKind::Fifo,
                        _ => EntryKind::Socket,
                    },
                    *node,
                ),
            };
            by_path.insert(op.path(), node);
            expect.insert(op.path().to_string(), (kind, node));
        }
        if seen.len() != expect.len() {
            let extra: Vec<&String> = seen.keys().filter(|k| !expect.contains_key(*k)).collect();
            let missing: Vec<&String> = expect.keys().filter(|k| !seen.contains_key(*k)).collect();
            return Err(fail(format!(
                "reader lists unexpected {extra:?}, misses {missing:?}"
            )));
        }
        let mut a = vec![0u8; 65536];
        let mut b = vec![0u8; 65536];
        let mut raw = vec![0u8; 65536];
        for (path, (kind, node)) in &expect {
            let Some(&(got_kind, size)) = seen.get(path) else {
                return Err(fail(format!("{path:?} is missing")));
            };
            if got_kind != *kind {
                return Err(fail(format!(
                    "{path:?} is a {got_kind:?}, planned {kind:?}"
                )));
            }
            match *kind {
                EntryKind::Symlink => {
                    let SourceKind::Symlink { target } = &tree.node(*node).kind else {
                        continue;
                    };
                    let got = udf
                        .read_symlink(dev, Path::new(path))
                        .map_err(|e| fail(e.to_string()))?;
                    if got.to_string_lossy() != *target {
                        return Err(fail(format!(
                            "{path:?} points at {got:?}, planned {target:?}"
                        )));
                    }
                }
                EntryKind::Regular => {
                    let Some((lba, len)) = p.payload.extent_of(tree, *node) else {
                        continue;
                    };
                    if size != len {
                        return Err(fail(format!("{path:?} is {size} bytes, planned {len}")));
                    }
                    if len == 0 {
                        continue;
                    }
                    // The UDF reader must return the bytes at the shared
                    // extent: compare its first and last chunk with the
                    // raw sectors.
                    let n = len.min(a.len() as u64) as usize;
                    let tail_off = len - n as u64;
                    {
                        let mut rd = udf
                            .open_file_ro(dev, Path::new(path))
                            .map_err(|e| fail(e.to_string()))?;
                        rd.read_exact(&mut a[..n])?;
                        rd.seek(SeekFrom::Start(tail_off))?;
                        rd.read_exact(&mut b[..n])?;
                    }
                    let base = u64::from(lba) * SECTOR;
                    dev.read_at(base, &mut raw[..n])?;
                    if raw[..n] != a[..n] {
                        return Err(fail(format!(
                            "{path:?}: UDF data is not the shared payload"
                        )));
                    }
                    dev.read_at(base + tail_off, &mut raw[..n])?;
                    if raw[..n] != b[..n] {
                        return Err(fail(format!(
                            "{path:?}: UDF data is not the shared payload"
                        )));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn summary(&self) -> Vec<(String, String)> {
        vec![
            ("revision".into(), self.format.revision.to_string()),
            ("label".into(), self.format.logical_volume_id()),
            ("volume id".into(), self.format.volume_id.clone()),
            (
                "partition".into(),
                format!("sectors {}..{}", self.partition.start, self.partition.end()),
            ),
        ]
    }
}

fn walk(
    fs: &mut Udf,
    dev: &mut dyn BlockDevice,
    dir: &str,
    out: &mut BTreeMap<String, (EntryKind, u64)>,
) -> crate::Result<()> {
    let list = Filesystem::list(fs, dev, Path::new(if dir.is_empty() { "/" } else { dir }))?;
    for e in list {
        let p = format!("{dir}/{}", e.name);
        let a = fs.getattr(dev, Path::new(&p))?;
        out.insert(p.clone(), (a.kind, a.size));
        if a.kind == EntryKind::Dir {
            walk(fs, dev, &p, out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::UdfNamer;

    #[test]
    fn namer_truncates_and_dedupes() {
        let mut n = UdfNamer::default();
        assert_eq!(n.map("a.txt"), ("a.txt".into(), false, false));
        let long = format!("{}.txt", "x".repeat(300));
        let (a, changed, truncated) = n.map(&long);
        assert!(changed && truncated);
        assert!(a.ends_with(".txt") && super::cs0_len(&a) <= 255);
        let (b, _, _) = n.map(&long);
        assert_ne!(a, b);
        assert!(b.ends_with("~1.txt") && super::cs0_len(&b) <= 255);
        let wide = "✓".repeat(200);
        let (c, _, t) = n.map(&wide);
        assert!(t && super::cs0_len(&c) <= 255 && c.chars().count() == 127);
    }
}
