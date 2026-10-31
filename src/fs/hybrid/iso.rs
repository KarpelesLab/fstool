//! The ISO 9660 view: the primary hierarchy (with Rock Ridge) and the
//! Joliet hierarchy, sharing one volume descriptor set.

use std::collections::BTreeMap;
use std::path::Path;

use crate::block::BlockDevice;
use crate::fs::iso9660::placed::{
    BootImage, Encoding, Hierarchy, IsoLayout, MAX_SECTION_BYTES, NodeKind, PlacedIso, RockRidge,
    VolumeInfo,
};
use crate::fs::iso9660::{Iso9660, ReadView};
use crate::fs::{DeviceKind, EntryKind, Filesystem};

use super::error::{HybridError, Result};
use super::names::{IsoNamer, JolietNamer, iso_label, joliet_label};
use super::plan::SECTOR;
use super::report::{HybridReport, OmitReason, ReportKind};
use super::source::{NodeId, SourceKind, SourceTree};
use super::view::{Extent, HybridView, Placement, SectorRequest, ViewId, ViewInput, ViewNeeds};
use super::{
    BootEmulation, BootOptions, BootPlatform, HybridOptions, IsoLevel, IsoOptions, JolietOptions,
};

/// What a reader of one hierarchy should find at one path.
#[derive(Debug, Clone)]
struct Expect {
    kind: EntryKind,
    size: u64,
    /// The source node (to resolve the payload LBA at `place`).
    node: NodeId,
    lba: u32,
    symlink: Option<String>,
}

/// One hierarchy under construction.
struct Built {
    hier: Hierarchy,
    /// (hierarchy node, source node) of every file.
    files: Vec<(usize, NodeId)>,
    /// Reader path → expectation.
    expect: BTreeMap<String, Expect>,
}

/// The ISO 9660 + Joliet view. Built by [`super::build_views`] from
/// [`HybridOptions::iso`] and [`HybridOptions::joliet`].
pub struct IsoView {
    iso_opts: IsoOptions,
    joliet_opts: JolietOptions,
    volume_name: String,
    create_date: i64,
    placed: Option<PlacedIso>,
    layout: Option<IsoLayout>,
    primary_files: Vec<(usize, NodeId)>,
    joliet_files: Vec<(usize, NodeId)>,
    expect: Vec<(ReadView, BTreeMap<String, Expect>)>,
    boot_nodes: Vec<NodeId>,
    meta_sectors: u32,
}

impl IsoView {
    /// The view `opts` describes.
    pub fn new(opts: &HybridOptions) -> Self {
        Self {
            iso_opts: opts.iso.clone(),
            joliet_opts: opts.joliet.clone(),
            volume_name: opts.volume_name.clone(),
            create_date: opts.create_date,
            placed: None,
            layout: None,
            primary_files: Vec::new(),
            joliet_files: Vec::new(),
            expect: Vec::new(),
            boot_nodes: Vec::new(),
            meta_sectors: 0,
        }
    }

    fn boot_node(tree: &SourceTree, b: &BootOptions) -> Result<NodeId> {
        let n = tree
            .lookup(&b.image)
            .ok_or_else(|| HybridError::UnknownPath {
                option: "El Torito boot image",
                path: b.image.clone(),
            })?;
        if !matches!(tree.node(n).kind, SourceKind::File { .. }) {
            return Err(HybridError::InvalidOption(format!(
                "El Torito boot image {:?} is not a regular file",
                b.image
            )));
        }
        Ok(n)
    }

    fn build(
        &self,
        input: &ViewInput<'_>,
        view: ViewId,
        encoding: Encoding,
        rock_ridge: bool,
        report: &mut HybridReport,
    ) -> Result<Built> {
        let tree = input.tree;
        let level = self.iso_opts.level;
        let joliet = encoding == Encoding::Joliet;
        let multi = level == IsoLevel::L3;
        let max_joliet = if self.joliet_opts.long_names { 103 } else { 64 };
        let root = tree.node(SourceTree::ROOT);
        let links = tree.links_of();
        let root_rr = rock_ridge.then(|| rr_attrs(tree, &links, input, view, SourceTree::ROOT, ""));
        let mut b = Built {
            hier: Hierarchy::new(encoding, root.meta.mtime, root_rr),
            files: Vec::new(),
            expect: BTreeMap::new(),
        };
        let mut mapped = 0usize;
        let mut specials = 0usize;
        let mut stack: Vec<(NodeId, usize, String)> =
            vec![(SourceTree::ROOT, Hierarchy::ROOT, String::new())];
        while let Some((src, dst, path)) = stack.pop() {
            let mut iso_namer = IsoNamer::default();
            let mut j_namer = JolietNamer::default();
            for &c in tree.children(src) {
                if !input.visibility.visible(view, c) {
                    continue;
                }
                let node = tree.node(c);
                let tree_path = tree.path_of(c);
                let is_dir = node.kind == SourceKind::Dir;
                // Kinds the hierarchy cannot hold.
                let (kind_name, special) = match &node.kind {
                    SourceKind::Symlink { .. } => ("symlink", true),
                    SourceKind::Device { kind, .. } => (
                        match kind {
                            DeviceKind::Char | DeviceKind::Block => "device",
                            DeviceKind::Fifo => "fifo",
                            DeviceKind::Socket => "socket",
                        },
                        true,
                    ),
                    _ => ("", false),
                };
                if special && rock_ridge {
                    specials += 1;
                }
                if special && !rock_ridge {
                    report.push(
                        view,
                        tree_path,
                        ReportKind::Omitted(OmitReason::Unrepresentable { kind: kind_name }),
                    );
                    continue;
                }
                let size = match node.kind {
                    SourceKind::File { content } => tree.content(content).len,
                    _ => 0,
                };
                if size > u64::from(u32::MAX) && !multi {
                    report.push(
                        view,
                        tree_path,
                        ReportKind::Omitted(OmitReason::TooLarge {
                            size,
                            limit: u64::from(u32::MAX),
                        }),
                    );
                    continue;
                }
                let m = if joliet {
                    j_namer.map(&node.name, max_joliet)
                } else {
                    iso_namer.map(&node.name, is_dir, level)
                };
                if m.changed {
                    if rock_ridge {
                        mapped += 1;
                    } else {
                        let kind = if m.truncated {
                            ReportKind::NameTruncated {
                                from: node.name.clone(),
                                to: m.display.clone(),
                            }
                        } else {
                            ReportKind::NameMapped {
                                from: node.name.clone(),
                                to: m.display.clone(),
                            }
                        };
                        report.push(view, tree_path.clone(), kind);
                    }
                }
                if !node.xattrs.is_empty() {
                    report.push(
                        view,
                        tree_path.clone(),
                        ReportKind::MetadataDropped { what: "xattrs" },
                    );
                }
                let rr = rock_ridge.then(|| rr_attrs(tree, &links, input, view, c, &node.name));
                let kind = match &node.kind {
                    SourceKind::Dir => NodeKind::Dir,
                    SourceKind::File { .. } => NodeKind::File { lba: 0, size },
                    _ => NodeKind::Special,
                };
                let id = b
                    .hier
                    .add(dst, m.value.clone(), kind, node.meta.mtime, rr)
                    .map_err(HybridError::Fs)?;
                let shown = if rock_ridge {
                    node.name.clone()
                } else {
                    m.display.clone()
                };
                let reader_path = format!("{path}/{shown}");
                let (ekind, symlink) = match &node.kind {
                    SourceKind::Dir => (EntryKind::Dir, None),
                    SourceKind::File { .. } => (EntryKind::Regular, None),
                    SourceKind::Symlink { target } => (EntryKind::Symlink, Some(target.clone())),
                    SourceKind::Device { .. } => (EntryKind::Regular, None),
                };
                b.expect.insert(
                    reader_path.clone(),
                    Expect {
                        kind: ekind,
                        size,
                        node: c,
                        lba: 0,
                        symlink,
                    },
                );
                if is_dir {
                    if tree.depth(c) >= 8 {
                        report.push(
                            view,
                            tree_path,
                            ReportKind::DepthExceeded {
                                depth: tree.depth(c) + 1,
                            },
                        );
                    }
                    stack.push((c, id, reader_path));
                } else if matches!(node.kind, SourceKind::File { .. }) {
                    b.files.push((id, c));
                }
            }
        }
        if specials > 0 {
            report.push(
                view,
                "/",
                ReportKind::Note(format!(
                    "{specials} symlinks / device nodes exist through Rock Ridge only; \
                     readers without it see them as empty files"
                )),
            );
        }
        if mapped > 0 {
            report.push(
                view,
                "/",
                ReportKind::Note(format!(
                    "{mapped} names were mapped to ECMA-119 identifiers; Rock Ridge \
                     readers see the original names"
                )),
            );
        }
        Ok(b)
    }
}

/// Rock Ridge attributes of `n` in `view`: its link count counts only
/// the names (or subdirectories) visible there.
fn rr_attrs(
    tree: &SourceTree,
    links: &[Vec<NodeId>],
    input: &ViewInput<'_>,
    view: ViewId,
    n: NodeId,
    name: &str,
) -> RockRidge {
    let node = tree.node(n);
    let perm = u32::from(node.meta.mode & 0o7777);
    let mut rr = RockRidge::new(name, 0);
    rr.uid = node.meta.uid;
    rr.gid = node.meta.gid;
    rr.mtime = node.meta.mtime;
    rr.atime = node.meta.atime;
    rr.ctime = node.meta.ctime;
    match &node.kind {
        SourceKind::Dir => {
            rr.mode = 0o040_000 | perm;
            let subdirs = tree
                .children(n)
                .iter()
                .filter(|&&c| {
                    tree.node(c).kind == SourceKind::Dir && input.visibility.visible(view, c)
                })
                .count();
            rr.nlink = 2 + subdirs as u32;
        }
        SourceKind::File { content } => {
            rr.mode = 0o100_000 | perm;
            let n = links[*content]
                .iter()
                .filter(|&&x| input.visibility.visible(view, x))
                .count();
            rr.nlink = n.max(1) as u32;
        }
        SourceKind::Symlink { target } => {
            rr.mode = 0o120_000 | perm;
            rr.symlink = Some(target.clone());
        }
        SourceKind::Device { kind, major, minor } => {
            rr.mode = perm
                | match kind {
                    DeviceKind::Char => 0o020_000,
                    DeviceKind::Block => 0o060_000,
                    DeviceKind::Fifo => 0o010_000,
                    DeviceKind::Socket => 0o140_000,
                };
            if matches!(kind, DeviceKind::Char | DeviceKind::Block) {
                rr.rdev = Some((*major, *minor));
            }
        }
    }
    rr
}

impl HybridView for IsoView {
    fn id(&self) -> ViewId {
        ViewId::Iso9660
    }

    fn covers(&self) -> Vec<ViewId> {
        let mut v = Vec::new();
        if self.iso_opts.enabled {
            v.push(ViewId::Iso9660);
        }
        if self.joliet_opts.enabled {
            v.push(ViewId::Joliet);
        }
        v
    }

    fn required_payloads(&self, tree: &SourceTree) -> Result<Vec<NodeId>> {
        self.iso_opts
            .boot
            .iter()
            .map(|b| Self::boot_node(tree, b))
            .collect()
    }

    fn prepare(&mut self, input: &ViewInput<'_>, report: &mut HybridReport) -> Result<ViewNeeds> {
        let tree = input.tree;
        // The primary hierarchy is mandatory (the PVD points at it); with
        // the ISO 9660 view disabled it is an empty root.
        let rr = self.iso_opts.enabled && self.iso_opts.rock_ridge;
        let primary = if self.iso_opts.enabled {
            self.build(input, ViewId::Iso9660, Encoding::Primary, rr, report)?
        } else {
            Built {
                hier: Hierarchy::new(Encoding::Primary, tree.node(0).meta.mtime, None),
                files: Vec::new(),
                expect: BTreeMap::new(),
            }
        };
        if self.iso_opts.enabled && !rr {
            report.push(
                ViewId::Iso9660,
                "/",
                ReportKind::Note(
                    "without Rock Ridge the primary hierarchy carries no permissions, \
                     owners, symlinks or device nodes"
                        .into(),
                ),
            );
        }
        let joliet = if self.joliet_opts.enabled {
            report.push(
                ViewId::Joliet,
                "/",
                ReportKind::Note(
                    "Joliet carries no permissions, owners, symlinks or device nodes".into(),
                ),
            );
            Some(self.build(input, ViewId::Joliet, Encoding::Joliet, false, report)?)
        } else {
            None
        };

        let wanted_id = self
            .iso_opts
            .volume_id
            .clone()
            .unwrap_or_else(|| self.volume_name.clone());
        let volume_id = iso_label(&wanted_id);
        if self.iso_opts.enabled && volume_id != wanted_id {
            report.push(
                ViewId::Iso9660,
                "/",
                ReportKind::LabelMapped {
                    from: wanted_id,
                    to: volume_id.clone(),
                },
            );
        }
        let wanted_j = self
            .joliet_opts
            .volume_id
            .clone()
            .unwrap_or_else(|| self.volume_name.clone());
        let joliet_volume_id = joliet_label(&wanted_j);
        if self.joliet_opts.enabled && joliet_volume_id != wanted_j {
            report.push(
                ViewId::Joliet,
                "/",
                ReportKind::LabelMapped {
                    from: wanted_j,
                    to: joliet_volume_id.clone(),
                },
            );
        }
        let o = &self.iso_opts;
        let info = VolumeInfo {
            system_id: o.system_id.clone(),
            volume_id,
            joliet_volume_id,
            volume_set_id: o.volume_set_id.clone(),
            publisher_id: o.publisher_id.clone(),
            preparer_id: o.preparer_id.clone(),
            application_id: o.application_id.clone(),
            copyright_file: o.copyright_file.clone(),
            abstract_file: o.abstract_file.clone(),
            bibliographic_file: o.bibliographic_file.clone(),
            create_date: if self.create_date != 0 {
                self.create_date
            } else {
                input.create_date
            },
        };
        let mut placed = PlacedIso::new(info, primary.hier);
        placed.rock_ridge = rr;
        placed.multi_extent = o.level == IsoLevel::L3;
        placed.section_bytes = MAX_SECTION_BYTES;
        self.primary_files = primary.files;
        self.expect.clear();
        if self.iso_opts.enabled {
            self.expect.push((
                if rr {
                    ReadView::RockRidge
                } else {
                    ReadView::Primary
                },
                primary.expect,
            ));
        }
        if let Some(j) = joliet {
            placed.joliet = Some(j.hier);
            self.joliet_files = j.files;
            self.expect.push((ReadView::Joliet, j.expect));
        }

        // El Torito: one entry per option, the first is the default.
        self.boot_nodes.clear();
        for b in &o.boot {
            let n = Self::boot_node(tree, b)?;
            self.boot_nodes.push(n);
            let len = match tree.node(n).kind {
                SourceKind::File { content } => tree.content(content).len,
                _ => 0,
            };
            let (media, count) = match b.emulation {
                BootEmulation::NoEmulation => {
                    let count = match b.load_sectors {
                        Some(c) => u64::from(c),
                        None if b.platform == BootPlatform::X86 => 4,
                        None => len.div_ceil(512),
                    };
                    if count > u64::from(u16::MAX) {
                        return Err(HybridError::TooLarge {
                            what: format!("El Torito load size of {:?}", b.image),
                            size: count * 512,
                            limit: u64::from(u16::MAX) * 512,
                        });
                    }
                    (0u8, count as u16)
                }
                BootEmulation::Floppy12 => (1, 1),
                BootEmulation::Floppy144 => (2, 1),
                BootEmulation::Floppy288 => (3, 1),
                BootEmulation::HardDisk => (4, 1),
            };
            let need = match b.emulation {
                BootEmulation::Floppy12 => Some(1_228_800),
                BootEmulation::Floppy144 => Some(1_474_560),
                BootEmulation::Floppy288 => Some(2_949_120),
                _ => None,
            };
            if let Some(need) = need
                && len != need
            {
                return Err(HybridError::InvalidOption(format!(
                    "El Torito floppy image {:?} is {len} bytes; the emulated floppy needs {need}",
                    b.image
                )));
            }
            if len == 0 {
                return Err(HybridError::InvalidOption(format!(
                    "El Torito boot image {:?} is empty",
                    b.image
                )));
            }
            let mut img = BootImage::no_emulation(0, count);
            img.platform = match b.platform {
                BootPlatform::X86 => 0,
                BootPlatform::PowerPc => 1,
                BootPlatform::Mac => 2,
                BootPlatform::Efi => 0xEF,
            };
            img.media_type = media;
            img.load_segment = b.load_segment;
            img.id_string = b.id_string.clone();
            placed.boot.push(img);
        }

        self.meta_sectors = placed.metadata_sectors().map_err(HybridError::Fs)?;
        let vrs = placed.descriptor_sectors();
        self.placed = Some(placed);
        Ok(ViewNeeds {
            vrs_sectors: vrs,
            head: vec![SectorRequest::new("iso9660 metadata", self.meta_sectors)],
            ..ViewNeeds::default()
        })
    }

    fn place(&mut self, p: &Placement<'_>) -> Result<Vec<(String, Extent)>> {
        let tree = p.tree;
        let placed = self.placed.as_mut().expect("prepared");
        let extent = |n: NodeId| -> Result<(u32, u64)> {
            p.payload.extent_of(tree, n).ok_or_else(|| {
                HybridError::InvalidTree(format!("{} has no payload", tree.path_of(n)))
            })
        };
        for &(id, n) in &self.primary_files {
            let (lba, len) = extent(n)?;
            placed.primary.set_extent(id, lba, len)?;
        }
        if let Some(j) = placed.joliet.as_mut() {
            for &(id, n) in &self.joliet_files {
                let (lba, len) = extent(n)?;
                j.set_extent(id, lba, len)?;
            }
        }
        for (img, &n) in placed.boot.iter_mut().zip(&self.boot_nodes) {
            img.load_rba = extent(n)?.0;
        }
        for (_, exp) in &mut self.expect {
            for e in exp.values_mut() {
                if e.kind == EntryKind::Regular
                    && let Some((lba, _)) = p.payload.extent_of(tree, e.node)
                {
                    e.lba = lba;
                }
            }
        }
        let start = p.own.head[0].lba;
        let layout = placed.layout(start).map_err(HybridError::Fs)?;
        if layout.sectors() != self.meta_sectors {
            return Err(HybridError::InvalidTree(format!(
                "iso9660 metadata resized from {} to {} sectors during placement",
                self.meta_sectors,
                layout.sectors()
            )));
        }
        let regions = layout
            .regions()
            .iter()
            .map(|r| {
                (
                    format!("iso9660 {}", r.label),
                    Extent::new(r.lba, r.sectors),
                )
            })
            .collect();
        self.layout = Some(layout);
        Ok(regions)
    }

    fn write(&self, dev: &mut dyn BlockDevice, p: &Placement<'_>) -> Result<()> {
        let placed = self.placed.as_ref().expect("prepared");
        let layout = self.layout.as_ref().expect("placed");
        placed
            .write(dev, layout, p.total_sectors)
            .map_err(HybridError::Fs)
    }

    fn verify(&self, dev: &mut dyn BlockDevice, p: &Placement<'_>) -> Result<()> {
        let fail = |view: ViewId, detail: String| HybridError::Verify { view, detail };
        let mut fs = Iso9660::open(dev).map_err(|e| fail(ViewId::Iso9660, e.to_string()))?;
        if fs.pvd.volume_space_size != p.total_sectors {
            return Err(fail(
                ViewId::Iso9660,
                format!(
                    "volume space is {} sectors, planned {}",
                    fs.pvd.volume_space_size, p.total_sectors
                ),
            ));
        }
        let placed = self.placed.as_ref().expect("prepared");
        if !placed.boot.is_empty() {
            let cat = fs
                .boot
                .clone()
                .ok_or_else(|| fail(ViewId::Iso9660, "El Torito catalog missing".into()))?;
            let layout = self.layout.as_ref().expect("placed");
            let lba = layout.boot_catalog_lba().expect("bootable");
            let mut v = [0u8; 32];
            dev.read_at(u64::from(lba) * SECTOR, &mut v)?;
            let sum = v.chunks(2).fold(0u16, |a, w| {
                a.wrapping_add(u16::from_le_bytes([w[0], w[1]]))
            });
            if sum != 0 || v[30] != 0x55 || v[31] != 0xAA {
                return Err(fail(
                    ViewId::Iso9660,
                    "El Torito validation entry checksum is wrong".into(),
                ));
            }
            if cat.default_entry.load_rba != placed.boot[0].load_rba {
                return Err(fail(
                    ViewId::Iso9660,
                    "El Torito default entry points elsewhere".into(),
                ));
            }
        }
        for (view, expect) in &self.expect {
            let vid = if *view == ReadView::Joliet {
                ViewId::Joliet
            } else {
                ViewId::Iso9660
            };
            fs.set_read_view(*view)
                .map_err(|e| fail(vid, e.to_string()))?;
            let mut seen = BTreeMap::new();
            walk(&mut fs, dev, "", &mut seen).map_err(|e| fail(vid, e.to_string()))?;
            if seen.len() != expect.len() {
                let extra: Vec<&String> =
                    seen.keys().filter(|k| !expect.contains_key(*k)).collect();
                let missing: Vec<&String> =
                    expect.keys().filter(|k| !seen.contains_key(*k)).collect();
                return Err(fail(
                    vid,
                    format!("reader lists unexpected {extra:?}, misses {missing:?}"),
                ));
            }
            for (path, e) in expect {
                let Some(&(kind, size, lba)) = seen.get(path) else {
                    return Err(fail(vid, format!("{path:?} is missing")));
                };
                let want_kind = if *view == ReadView::Primary || *view == ReadView::Joliet {
                    // Without Rock Ridge every non-directory is a file.
                    if e.kind == EntryKind::Dir {
                        EntryKind::Dir
                    } else {
                        EntryKind::Regular
                    }
                } else {
                    e.kind
                };
                if kind != want_kind {
                    return Err(fail(
                        vid,
                        format!("{path:?} is a {kind:?}, planned {want_kind:?}"),
                    ));
                }
                if e.kind == EntryKind::Regular && (size != e.size || (e.size > 0 && lba != e.lba))
                {
                    return Err(fail(
                        vid,
                        format!(
                            "{path:?}: {size} bytes at LBA {lba}, planned {} at {}",
                            e.size, e.lba
                        ),
                    ));
                }
                if let Some(t) = &e.symlink {
                    let got = fs
                        .read_symlink(dev, Path::new(path))
                        .map_err(|e| fail(vid, e.to_string()))?;
                    if got.to_str() != Some(t.as_str()) {
                        return Err(fail(
                            vid,
                            format!("{path:?} links to {got:?}, planned {t:?}"),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn summary(&self) -> Vec<(String, String)> {
        let mut v = Vec::new();
        if let Some(p) = &self.placed {
            if self.iso_opts.enabled {
                v.push(("volume id".into(), p.info.volume_id.clone()));
                v.push((
                    "level".into(),
                    match self.iso_opts.level {
                        IsoLevel::L1 => "1",
                        IsoLevel::L2 => "2",
                        IsoLevel::L3 => "3",
                    }
                    .into(),
                ));
                v.push(("rock ridge".into(), p.rock_ridge.to_string()));
            }
            if p.joliet.is_some() {
                v.push(("joliet volume id".into(), p.info.joliet_volume_id.clone()));
            }
            if !p.boot.is_empty() {
                v.push(("el torito entries".into(), p.boot.len().to_string()));
            }
        }
        v
    }
}

/// Collect `path → (kind, size, extent LBA)` of everything below `dir`.
fn walk(
    fs: &mut Iso9660,
    dev: &mut dyn BlockDevice,
    dir: &str,
    out: &mut BTreeMap<String, (EntryKind, u64, u32)>,
) -> crate::Result<()> {
    let list = fs.list(dev, Path::new(if dir.is_empty() { "/" } else { dir }))?;
    for e in list {
        let p = format!("{dir}/{}", e.name);
        let kind = if e.kind == EntryKind::Dir {
            EntryKind::Dir
        } else {
            fs.getattr(dev, Path::new(&p))?.kind
        };
        let kind = match kind {
            EntryKind::Dir | EntryKind::Symlink => kind,
            _ => EntryKind::Regular,
        };
        out.insert(p.clone(), (kind, e.size, e.inode));
        if kind == EntryKind::Dir {
            walk(fs, dev, &p, out)?;
        }
    }
    Ok(())
}
