//! The HFS+ view: an `Apple_HFS` partition enclosing the payloads it
//! lists, its file records pointing at the same sectors ISO 9660 uses.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use crate::block::{BlockDevice, SlicedBackend};
use crate::fs::hfs_plus::size_plan::{GeneratedBudget, HfsPlusSizePlan};
use crate::fs::hfs_plus::writer::format_reserved_head_blocks;
use crate::fs::hfs_plus::{FormatOpts, HfsPlus, VolumeFinderInfo};
use crate::fs::{DeviceKind, EntryKind, Filesystem, FsSizePlan};

use super::apm;
use super::error::{HybridError, Result};
use super::names::HfsNamer;
use super::plan::SECTOR;
use super::report::{HybridReport, ReportKind};
use super::source::{NodeId, SourceKind, SourceTree};
use super::view::{
    ByteRequest, Extent, HybridView, Placement, ViewId, ViewInput, ViewNeeds, WrapRequest,
};
use super::{HfsOptions, HybridOptions};

const XATTR_RESOURCE_FORK: &str = "com.apple.ResourceFork";
const XATTR_FINDER_INFO: &str = "com.apple.FinderInfo";

#[derive(Debug, Clone)]
enum Op {
    Dir {
        path: String,
        node: NodeId,
    },
    File {
        path: String,
        node: NodeId,
    },
    Link {
        path: String,
        target: String,
    },
    Symlink {
        path: String,
        node: NodeId,
        target: String,
    },
    Device {
        path: String,
        node: NodeId,
    },
}

/// The HFS+ view. Built by [`super::build_views`] from
/// [`HybridOptions::hfs`].
pub struct HfsView {
    opts: HfsOptions,
    volume_name: String,
    create_date: i64,
    format: FormatOpts,
    ops: Vec<Op>,
    /// Tree path → HFS+ path of every node in the view.
    paths: BTreeMap<NodeId, String>,
    sectors_per_block: u32,
    head_blocks: u32,
    pool_blocks: u32,
    tail_blocks: u32,
    total_blocks: u32,
    start_lba: u32,
}

impl HfsView {
    /// The view `opts` describes.
    pub fn new(opts: &HybridOptions) -> Self {
        Self {
            opts: opts.hfs.clone(),
            volume_name: opts
                .hfs
                .volume_name
                .clone()
                .unwrap_or_else(|| opts.volume_name.clone()),
            create_date: opts.create_date,
            format: FormatOpts::default(),
            ops: Vec::new(),
            paths: BTreeMap::new(),
            sectors_per_block: 1,
            head_blocks: 0,
            pool_blocks: 0,
            tail_blocks: 0,
            total_blocks: 0,
            start_lba: 0,
        }
    }

    fn hfs_path(&self, tree: &SourceTree, option: &'static str, path: &str) -> Result<String> {
        let n = tree.lookup(path).ok_or_else(|| HybridError::UnknownPath {
            option,
            path: path.to_string(),
        })?;
        if n == SourceTree::ROOT {
            return Ok("/".into());
        }
        self.paths
            .get(&n)
            .cloned()
            .ok_or_else(|| HybridError::UnknownPath {
                option,
                path: path.to_string(),
            })
    }

    fn slice<'a>(
        &self,
        dev: &'a mut dyn BlockDevice,
    ) -> Result<SlicedBackend<'a, dyn BlockDevice + 'a>> {
        let start = u64::from(self.start_lba) * SECTOR;
        let len = u64::from(self.total_blocks) * u64::from(self.format.block_size);
        Ok(SlicedBackend::new(dev, start, len)?)
    }
}

fn clamp_time(t: i64) -> u32 {
    t.clamp(0, i64::from(u32::MAX)) as u32
}

impl HybridView for HfsView {
    fn id(&self) -> ViewId {
        ViewId::HfsPlus
    }

    fn payload_alignment(&self) -> u32 {
        (self.opts.block_size / SECTOR as u32).max(1)
    }

    fn wraps_payload(&self) -> bool {
        true
    }

    fn prepare(&mut self, input: &ViewInput<'_>, report: &mut HybridReport) -> Result<ViewNeeds> {
        let tree = input.tree;
        let bs = self.opts.block_size;
        if !bs.is_power_of_two() || u64::from(bs) < SECTOR {
            return Err(HybridError::InvalidOption(format!(
                "HFS+ block size {bs} must be a power of two of at least 2048 \
                 (an ISO 9660 sector)"
            )));
        }
        let spb = bs / SECTOR as u32;
        self.sectors_per_block = spb;

        let mut namer = HfsNamer::new(self.opts.case_sensitive);
        let vol = namer.map(&self.volume_name);
        if vol.changed {
            report.push(
                ViewId::HfsPlus,
                "/",
                ReportKind::LabelMapped {
                    from: self.volume_name.clone(),
                    to: vol.value.clone(),
                },
            );
        }
        let mut fo = FormatOpts {
            block_size: bs,
            volume_name: vol.value,
            case_sensitive: self.opts.case_sensitive,
            create_date: crate::fs::hfs_plus::hfs_date_from_unix(
                input.create_date.max(self.create_date),
            ),
            journaled: false,
            // The size plan raises this to what the tree needs.
            catalog_nodes: 4,
            ..FormatOpts::default()
        };

        // Walk the visible tree, mapping names per directory.
        self.ops.clear();
        self.paths.clear();
        let mut first_link: BTreeMap<usize, String> = BTreeMap::new();
        let mut plan = HfsPlusSizePlan::new(&fo);
        let mut pool: u64 = 0;
        let mut hardlinks = 0u64;
        let block = |len: u64| len.div_ceil(u64::from(bs));
        let max_inline = crate::fs::hfs_plus::attributes::max_inline_attr_size(
            crate::fs::hfs_plus::writer::DEFAULT_NODE_SIZE.max(4096),
        ) as u64;
        let mut stack: Vec<(NodeId, String)> = vec![(SourceTree::ROOT, String::new())];
        let root = tree.node(SourceTree::ROOT);
        if root.meta.mode != 0o755 || root.meta.uid != 0 || root.meta.gid != 0 {
            report.push(
                ViewId::HfsPlus,
                "/",
                ReportKind::MetadataDropped {
                    what: "root folder permissions and owner (always 0755 root)",
                },
            );
        }
        while let Some((src, dir)) = stack.pop() {
            let mut namer = HfsNamer::new(self.opts.case_sensitive);
            let mut todo = Vec::new();
            for &c in tree.children(src) {
                if !input.visibility.visible(ViewId::HfsPlus, c) {
                    continue;
                }
                let node = tree.node(c);
                let m = namer.map(&node.name);
                if m.changed {
                    let kind = if m.truncated {
                        ReportKind::NameTruncated {
                            from: node.name.clone(),
                            to: m.value.clone(),
                        }
                    } else {
                        ReportKind::NameMapped {
                            from: node.name.clone(),
                            to: m.value.clone(),
                        }
                    };
                    report.push(ViewId::HfsPlus, tree.path_of(c), kind);
                }
                let path = format!("{dir}/{}", m.value);
                self.paths.insert(c, path.clone());
                match &node.kind {
                    SourceKind::Dir => {
                        plan.add_dir(&path);
                        self.ops.push(Op::Dir {
                            path: path.clone(),
                            node: c,
                        });
                        todo.push((c, path));
                    }
                    SourceKind::File { content } => {
                        if let Some(target) = first_link.get(content) {
                            hardlinks += 1;
                            self.ops.push(Op::Link {
                                path,
                                target: target.clone(),
                            });
                        } else {
                            plan.add_file(&path, 0);
                            first_link.insert(*content, path.clone());
                            self.ops.push(Op::File { path, node: c });
                        }
                    }
                    SourceKind::Symlink { target } => {
                        plan.add_symlink(&path, target);
                        pool += block(target.len() as u64).max(1);
                        self.ops.push(Op::Symlink {
                            path,
                            node: c,
                            target: target.clone(),
                        });
                    }
                    SourceKind::Device { .. } => {
                        plan.add_device(&path);
                        self.ops.push(Op::Device { path, node: c });
                    }
                }
                if self.opts.xattrs {
                    for x in &node.xattrs {
                        let len = x.value.len() as u64;
                        match x.name.as_str() {
                            XATTR_FINDER_INFO => {}
                            XATTR_RESOURCE_FORK => {
                                pool += block(len);
                            }
                            _ => {
                                if len > max_inline {
                                    pool += block(len);
                                }
                            }
                        }
                        plan.add_xattr(&x.name, len);
                    }
                } else if !node.xattrs.is_empty() {
                    report.push(
                        ViewId::HfsPlus,
                        tree.path_of(c),
                        ReportKind::MetadataDropped { what: "xattrs" },
                    );
                }
            }
            // Depth-first in name order: push in reverse.
            for t in todo.into_iter().rev() {
                stack.push(t);
            }
        }
        if hardlinks > 0 {
            let b = GeneratedBudget {
                dirs: 1,
                files: 2 * hardlinks + first_link.len() as u64,
                ..GeneratedBudget::default()
            };
            plan.add_budget(&b);
        }
        plan.apply_to(&mut fo);
        // Slack for the catalog / attributes trees' own growth beyond the
        // plan, and the hard-link machinery.
        pool += 16;

        let payload_blocks = u64::from(input.payload.wrapped_sectors()) / u64::from(spb);
        let tail = 1024u64.div_ceil(u64::from(bs));
        // Fixed point: the head (bitmap, B-trees) grows with the volume.
        // Anything a step overshoots is left to the pool.
        let mut total = 16 + pool + payload_blocks + tail;
        for _ in 0..64 {
            let t32 = u32::try_from(total).map_err(|_| HybridError::TooLarge {
                what: "HFS+ volume (allocation blocks)".into(),
                size: total,
                limit: u64::from(u32::MAX),
            })?;
            let head = u64::from(format_reserved_head_blocks(&fo, t32)?);
            let need = (head + pool + payload_blocks + tail).max(8);
            if need <= total {
                break;
            }
            total = need;
        }
        let t32 = u32::try_from(total).map_err(|_| HybridError::TooLarge {
            what: "HFS+ volume (allocation blocks)".into(),
            size: total,
            limit: u64::from(u32::MAX),
        })?;
        let head = format_reserved_head_blocks(&fo, t32)?;
        // Whatever the fixed point left over goes to the pool.
        let pool = t32 - head - payload_blocks as u32 - tail as u32;
        self.head_blocks = head;
        self.pool_blocks = pool;
        self.tail_blocks = tail as u32;
        self.total_blocks = t32;
        self.format = fo;

        // Paths named by options must be in the view.
        for (opt, p) in [
            ("blessed folder", &self.opts.blessed_folder),
            ("open folder", &self.opts.open_folder),
        ] {
            if let Some(p) = p {
                let hp = self.hfs_path(tree, opt, p)?;
                let n = tree.lookup(p).expect("resolved");
                if tree.node(n).kind != SourceKind::Dir {
                    return Err(HybridError::InvalidOption(format!(
                        "{opt} {p:?} ({hp}) is not a directory"
                    )));
                }
            }
        }
        for (p, _) in &self.opts.finder_info {
            self.hfs_path(tree, "Finder info", p)?;
        }

        let mut needs = ViewNeeds::default();
        needs
            .system_area
            .push(ByteRequest::new("apple partition map", 0, apm::APM_BYTES));
        needs.wrap = Some(WrapRequest::new(
            (head + pool) * spb,
            self.tail_blocks * spb,
        ));
        Ok(needs)
    }

    fn place(&mut self, p: &Placement<'_>) -> Result<Vec<(String, Extent)>> {
        let w = p.wrap.ok_or_else(|| {
            HybridError::InvalidOption("HFS+ view placed without its partition".into())
        })?;
        let spb = self.sectors_per_block;
        if w.payload_start - w.start != (self.head_blocks + self.pool_blocks) * spb
            || w.end - w.start != self.total_blocks * spb
        {
            return Err(HybridError::InvalidTree(
                "HFS+ partition placed with a different size than planned".into(),
            ));
        }
        if u64::from(w.end) * 4 > u64::from(u32::MAX) {
            return Err(HybridError::TooLarge {
                what: "image addressed by the Apple Partition Map".into(),
                size: u64::from(w.end) * SECTOR,
                limit: u64::from(u32::MAX) * 512,
            });
        }
        self.start_lba = w.start;
        for op in &self.ops {
            if let Op::File { node, .. } = op
                && let Some((lba, len)) = p.payload.extent_of(p.tree, *node)
                && len > 0
                && (lba < w.payload_start || lba >= w.payload_end || (lba - w.start) % spb != 0)
            {
                return Err(HybridError::InvalidTree(format!(
                    "{}: payload at LBA {lba} is not a block of the HFS+ partition",
                    p.tree.path_of(*node)
                )));
            }
        }
        let head = Extent::new(w.start, self.head_blocks * spb);
        let pool = Extent::new(head.lba + head.sectors, self.pool_blocks * spb);
        let tail = Extent::new(w.payload_end, self.tail_blocks * spb);
        Ok(vec![
            ("hfs+ volume header + special files".into(), head),
            ("hfs+ private pool".into(), pool),
            ("hfs+ alternate volume header".into(), tail),
        ])
    }

    fn write(&self, dev: &mut dyn BlockDevice, p: &Placement<'_>) -> Result<()> {
        let tree = p.tree;
        let w = p.wrap.expect("placed");
        let map = apm::encode(
            p.total_sectors,
            w.start,
            w.end - w.start,
            &self.format.volume_name,
        );
        dev.write_at(0, &map)?;
        let bs = u64::from(self.format.block_size);
        let mut slice = self.slice(dev)?;
        let mut hfs = HfsPlus::format(&mut slice, &self.format)?;
        let spb = self.sectors_per_block;
        for op in &self.ops {
            match op {
                Op::Dir { path, node } => {
                    let m = tree.node(*node).meta;
                    hfs.create_dir(&mut slice, path, m.mode, m.uid, m.gid, clamp_time(m.mtime))?;
                }
                Op::File { path, node } => {
                    let m = tree.node(*node).meta;
                    let (lba, len) = p.payload.extent_of(tree, *node).unwrap_or((0, 0));
                    let (start, count) = if len == 0 {
                        (0, 0)
                    } else {
                        ((lba - w.start) / spb, len.div_ceil(bs) as u32)
                    };
                    hfs.create_file_placed(
                        path,
                        start,
                        count,
                        len,
                        m.mode,
                        m.uid,
                        m.gid,
                        clamp_time(m.mtime),
                    )?;
                }
                Op::Link { path, target } => {
                    hfs.create_hardlink(&mut slice, target, path)?;
                }
                Op::Symlink { path, node, target } => {
                    let m = tree.node(*node).meta;
                    hfs.create_symlink(
                        &mut slice,
                        path,
                        target,
                        m.mode,
                        m.uid,
                        m.gid,
                        clamp_time(m.mtime),
                    )?;
                }
                Op::Device { path, node } => {
                    let n = tree.node(*node);
                    let SourceKind::Device { kind, major, minor } = n.kind else {
                        unreachable!("planned as a device");
                    };
                    let m = n.meta;
                    hfs.create_device(
                        &mut slice,
                        path,
                        kind,
                        major,
                        minor,
                        m.mode,
                        m.uid,
                        m.gid,
                        clamp_time(m.mtime),
                    )?;
                }
            }
        }
        if self.opts.xattrs {
            for op in &self.ops {
                let (path, node) = match op {
                    Op::Dir { path, node }
                    | Op::File { path, node }
                    | Op::Symlink { path, node, .. }
                    | Op::Device { path, node } => (path, *node),
                    Op::Link { .. } => continue,
                };
                for x in &tree.node(node).xattrs {
                    if x.name == XATTR_RESOURCE_FORK && !matches!(op, Op::File { .. }) {
                        continue;
                    }
                    hfs.set_xattr(&mut slice, path, &x.name, &x.value)?;
                }
            }
            for x in &tree.node(SourceTree::ROOT).xattrs {
                if x.name != XATTR_RESOURCE_FORK {
                    hfs.set_xattr(&mut slice, "/", &x.name, &x.value)?;
                }
            }
        }
        for (path, info) in &self.opts.finder_info {
            let hp = self.hfs_path(tree, "Finder info", path)?;
            hfs.set_finder_info(&hp, info)?;
        }
        let mut vfi: VolumeFinderInfo = hfs.volume_finder_info()?;
        if let Some(b) = &self.opts.blessed_folder {
            let hp = self.hfs_path(tree, "blessed folder", b)?;
            vfi.set_blessed_folder(hfs.entry_info(&hp)?.cnid);
        }
        if let Some(o) = &self.opts.open_folder {
            let hp = self.hfs_path(tree, "open folder", o)?;
            vfi.set_open_folder(hfs.entry_info(&hp)?.cnid);
        }
        if let Some(id) = self.opts.volume_identifier {
            vfi.set_volume_identifier(id);
        }
        hfs.set_volume_finder_info(&vfi)?;
        hfs.flush(&mut slice)?;
        Ok(())
    }

    fn verify(&self, dev: &mut dyn BlockDevice, p: &Placement<'_>) -> Result<()> {
        let fail = |detail: String| HybridError::Verify {
            view: ViewId::HfsPlus,
            detail,
        };
        let w = p.wrap.expect("placed");
        // The partition map.
        let apm = crate::part::Apm::read(dev).map_err(|e| fail(format!("partition map: {e}")))?;
        use crate::part::PartitionTable;
        let found = apm.partitions().iter().any(|part| {
            part.start_lba * 512 == u64::from(w.start) * SECTOR
                && part.size_lba * 512 == u64::from(w.end - w.start) * SECTOR
        });
        if !found {
            return Err(fail(
                "the partition map has no entry for the HFS+ partition".into(),
            ));
        }
        let tree = p.tree;
        let bs = self.format.block_size;
        let mut slice = self.slice(dev)?;
        // Both volume headers.
        let len = slice.total_size();
        for (what, off) in [
            ("volume header", 1024u64),
            ("alternate volume header", len - 1024),
        ] {
            let mut sig = [0u8; 2];
            slice.read_at(off, &mut sig)?;
            if &sig != b"H+" && &sig != b"HX" {
                return Err(fail(format!("{what} signature is {sig:?}")));
            }
        }
        let mut hfs = HfsPlus::open(&mut slice).map_err(|e| fail(e.to_string()))?;
        let mut seen = BTreeMap::new();
        walk(&mut hfs, &mut slice, "", &mut seen).map_err(|e| fail(e.to_string()))?;
        let norm = crate::fs::hfs_plus::unicode::normalize_name;
        let mut expect: BTreeMap<String, (EntryKind, u64, NodeId)> = BTreeMap::new();
        for op in &self.ops {
            let (path, kind, node) = match op {
                Op::Dir { path, node } => (path, EntryKind::Dir, *node),
                Op::File { path, node } => (path, EntryKind::Regular, *node),
                Op::Link { path, target } => {
                    let n = self
                        .paths
                        .iter()
                        .find(|(_, v)| *v == target)
                        .map(|(k, _)| *k)
                        .expect("planned");
                    (path, EntryKind::Regular, n)
                }
                Op::Symlink { path, node, .. } => (path, EntryKind::Symlink, *node),
                Op::Device { path, node } => {
                    let k = match tree.node(*node).kind {
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
                    };
                    (path, k, *node)
                }
            };
            let disp: String = path
                .split('/')
                .map(|c| norm(&c.replace(':', "/")).replace('/', ":"))
                .collect::<Vec<_>>()
                .join("/");
            expect.insert(disp, (kind, 0, node));
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
        for (path, (kind, _, node)) in &expect {
            let Some(&(got_kind, size)) = seen.get(path) else {
                return Err(fail(format!("{path:?} is missing")));
            };
            if got_kind != *kind {
                return Err(fail(format!(
                    "{path:?} is a {got_kind:?}, planned {kind:?}"
                )));
            }
            if *kind != EntryKind::Regular {
                continue;
            }
            let Some((lba, len)) = p.payload.extent_of(tree, *node) else {
                continue;
            };
            if size != len {
                return Err(fail(format!("{path:?} is {size} bytes, planned {len}")));
            }
            if len == 0 {
                continue;
            }
            // The HFS+ reader must return the bytes at the shared extent:
            // compare its first and last chunk with the raw sectors.
            let n = (len.min(a.len() as u64)) as usize;
            let tail_off = len - n as u64;
            {
                let mut r = hfs
                    .open_file_ro(&mut slice, Path::new(path))
                    .map_err(|e| fail(e.to_string()))?;
                r.read_exact(&mut a[..n])?;
                std::io::Seek::seek(&mut r, std::io::SeekFrom::Start(tail_off))?;
                r.read_exact(&mut b[..n])?;
            }
            let base = u64::from(lba - w.start) * SECTOR;
            let mut raw = vec![0u8; n];
            slice.read_at(base, &mut raw)?;
            if raw != a[..n] {
                return Err(fail(format!(
                    "{path:?}: HFS+ data is not the shared payload"
                )));
            }
            slice.read_at(base + tail_off, &mut raw)?;
            if raw != b[..n] {
                return Err(fail(format!(
                    "{path:?}: HFS+ data is not the shared payload"
                )));
            }
        }
        let _ = bs;
        Ok(())
    }

    fn summary(&self) -> Vec<(String, String)> {
        vec![
            ("volume name".into(), self.format.volume_name.clone()),
            ("block size".into(), self.format.block_size.to_string()),
            ("blocks".into(), self.total_blocks.to_string()),
            (
                "case sensitive".into(),
                self.format.case_sensitive.to_string(),
            ),
        ]
    }
}

fn walk(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    dir: &str,
    out: &mut BTreeMap<String, (EntryKind, u64)>,
) -> crate::Result<()> {
    let list = Filesystem::list(fs, dev, Path::new(if dir.is_empty() { "/" } else { dir }))?;
    for e in list {
        // The hard-link private directory (its name starts with four
        // NULs) is HFS+ bookkeeping, not part of the tree.
        if e.name.starts_with('\0') {
            continue;
        }
        let p = format!("{dir}/{}", e.name);
        let a = fs.getattr(dev, Path::new(&p))?;
        out.insert(p.clone(), (a.kind, a.size));
        if a.kind == EntryKind::Dir {
            walk(fs, dev, &p, out)?;
        }
    }
    Ok(())
}
