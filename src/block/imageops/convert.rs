//! Streaming container conversion.

use std::path::Path;

use super::{COPY_CHUNK, open_source, same_file, write_beside};
use crate::Result;
use crate::block::BlockDevice;

/// A container kind, for a conversion target (and as reported for a
/// source).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ImageKind {
    /// Bare sectors in a file.
    Raw,
    /// Apple UDIF (`.dmg`); the format is [`ConvertOptions::udif`]'s.
    Udif,
    /// Apple `.sparseimage`.
    SparseImage,
    /// Apple `.sparsebundle` (a directory).
    SparseBundle,
    /// qcow2.
    Qcow2,
    /// Any other source container fstool reads (LUKS, DiskCopy, split
    /// archives, …). Not a valid target.
    Other,
}

impl ImageKind {
    /// The target kind a destination's extension names: `.dmg` → UDIF,
    /// `.sparseimage`, `.sparsebundle`, `.qcow2` / `.qcow` / `.q2`, and
    /// anything else raw.
    pub fn from_extension(path: &Path) -> Self {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);
        match ext.as_deref() {
            Some("dmg") => Self::Udif,
            Some("sparseimage") => Self::SparseImage,
            Some("sparsebundle") => Self::SparseBundle,
            Some("qcow2" | "qcow" | "q2") => Self::Qcow2,
            _ => Self::Raw,
        }
    }

    /// The kind of an existing image, by content.
    pub fn detect(path: &Path) -> Result<Self> {
        #[cfg(feature = "sparse-image")]
        {
            if crate::block::SparseBundleBackend::probe(path)? {
                return Ok(Self::SparseBundle);
            }
            if crate::block::SparseImageBackend::probe(path)? {
                return Ok(Self::SparseImage);
            }
        }
        if super::is_udif(path)? {
            return Ok(Self::Udif);
        }
        #[cfg(feature = "dmg")]
        if crate::block::dmg::probe_encrypted(path)? {
            return Ok(Self::Other);
        }
        #[cfg(feature = "qcow2")]
        if crate::block::Qcow2Backend::probe(path)? {
            return Ok(Self::Qcow2);
        }
        Ok(if path.is_file() {
            // Raw, or a container fstool unwraps (LUKS, DiskCopy, …).
            let mut dev = crate::block::FileBackend::open_read_only(path)?;
            let mut head = [0u8; 6];
            let n = dev.total_size().min(6) as usize;
            dev.read_at(0, &mut head[..n])?;
            if &head == b"LUKS\xba\xbe" {
                Self::Other
            } else {
                Self::Raw
            }
        } else {
            Self::Other
        })
    }

    /// A short name (`"raw"`, `"udif"`, …).
    pub fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Udif => "udif",
            Self::SparseImage => "sparseimage",
            Self::SparseBundle => "sparsebundle",
            Self::Qcow2 => "qcow2",
            Self::Other => "other",
        }
    }
}

/// What a conversion does with the source's UDIF resources other than
/// the ones the writer regenerates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ResourcePolicy {
    /// Carry them into a UDIF target. A target that cannot hold them (raw,
    /// sparse, qcow2, UDRW) is refused when there are any, rather than
    /// losing them silently.
    #[default]
    Keep,
    /// Drop them.
    Drop,
}

/// Resource types a re-encoding never carries over: `blkx` is rebuilt,
/// and `cSum` holds checksums of the old encoding. (`plst` is kept.)
#[cfg(feature = "dmg")]
const REGENERATED: [&str; 2] = [crate::block::dmg::BLKX_RESOURCE, "cSum"];

/// Options for [`convert_image`]. Construct with `Default` and assign.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConvertOptions {
    /// Target kind; `None` takes it from the destination's extension
    /// ([`ImageKind::from_extension`]).
    pub target: Option<ImageKind>,
    /// UDIF writer options for a UDIF target. Default: the writer's
    /// defaults (UDZO, CRC-32) with [`UdifLayout::Auto`].
    ///
    /// [`UdifLayout::Auto`]: crate::block::dmg::UdifLayout::Auto
    #[cfg(feature = "dmg-write")]
    pub udif: crate::block::dmg::UdifWriteOptions,
    /// For a UDIF source and UDIF target: reproduce the source's `blkx`
    /// map (names, IDs, block descriptors, free-space regions) instead of
    /// `udif.layout`. Default true.
    pub preserve_layout: bool,
    /// The source's other UDIF resources. Default [`ResourcePolicy::Keep`].
    pub resources: ResourcePolicy,
    /// Band size for a sparse target; 0 = hdiutil's default.
    pub sparse_band_size: u64,
    /// Passphrase for an encrypted source (LUKS, encrypted qcow2,
    /// `encrcdsa` `.dmg`). Encrypted sources are refused without one.
    pub password: Option<String>,
    /// What may be dropped from a UDIF source (its code signature, a
    /// legacy resource fork). Default: refuse.
    #[cfg(feature = "dmg")]
    pub policy: crate::block::dmg::UdifRewritePolicy,
}

impl Default for ConvertOptions {
    fn default() -> Self {
        Self {
            target: None,
            #[cfg(feature = "dmg-write")]
            udif: crate::block::dmg::UdifWriteOptions {
                layout: crate::block::dmg::UdifLayout::Auto,
                ..Default::default()
            },
            preserve_layout: true,
            resources: ResourcePolicy::Keep,
            sparse_band_size: 0,
            password: None,
            #[cfg(feature = "dmg")]
            policy: Default::default(),
        }
    }
}

/// What [`convert_image`] did.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ConvertReport {
    /// The source's kind.
    pub source: ImageKind,
    /// The target's kind.
    pub target: ImageKind,
    /// Logical bytes converted (the source's virtual size).
    pub bytes: u64,
    /// Source resource types dropped (regenerated ones, or all of them
    /// under [`ResourcePolicy::Drop`]).
    pub dropped_resources: Vec<String>,
    /// The UDIF writer's summary, for a UDIF target.
    #[cfg(feature = "dmg-write")]
    pub udif: Option<crate::block::dmg::UdifSummary>,
}

/// Convert the image at `src` into a new image at `dst`, streaming its
/// logical sectors through [`BlockDevice`] — no filesystem is read or
/// rebuilt, so this works the same for partitioned disks, bare volumes
/// and unknown contents.
///
/// Any readable source (raw, UDIF of any readable format — segmented
/// too —, sparse, qcow2, LUKS / encrypted `.dmg` with
/// [`ConvertOptions::password`]) converts to any writable target (raw,
/// UDIF in any writable format, `.sparseimage`, `.sparsebundle`, qcow2).
/// Every logical sector is reproduced; all-zero runs stay holes in sparse
/// targets. From a partitioned UDIF to UDIF the `blkx` map is preserved
/// (see [`ConvertOptions::preserve_layout`]); other resources follow
/// [`ConvertOptions::resources`]. A code-signed source follows
/// [`ConvertOptions::policy`] — the output is never signed.
///
/// The output is built in a hidden sibling of `dst` and renamed over it
/// only once complete: on failure `dst`, if it existed, is untouched.
pub fn convert_image(src: &Path, dst: &Path, opts: &ConvertOptions) -> Result<ConvertReport> {
    if same_file(src, dst) {
        return Err(crate::Error::InvalidArgument(
            "convert: source and destination are the same file".into(),
        ));
    }
    if crate::block::file::is_block_device(dst) {
        return Err(crate::Error::InvalidArgument(
            "convert: the destination must be an image file, not a block device".into(),
        ));
    }
    let target = opts
        .target
        .unwrap_or_else(|| ImageKind::from_extension(dst));
    let source = ImageKind::detect(src)?;
    #[cfg_attr(not(feature = "dmg"), allow(unused_mut))]
    let mut dropped: Vec<String> = Vec::new();

    // The source's UDIF metadata: layout and resources to carry.
    #[cfg(feature = "dmg")]
    let src_info = if source == ImageKind::Udif {
        let info = crate::block::dmg::inspect_udif(src)?;
        opts.policy.check(&info, "converting")?;
        Some(info)
    } else {
        None
    };
    #[cfg(feature = "dmg")]
    let carried: Vec<crate::block::dmg::UdifResource> = match &src_info {
        Some(info) => {
            let mut keep = Vec::new();
            for r in &info.resources.entries {
                let regenerated = REGENERATED.contains(&r.kind.as_str());
                if regenerated || opts.resources == ResourcePolicy::Drop {
                    if !regenerated && !dropped.contains(&r.kind) {
                        dropped.push(r.kind.clone());
                    }
                    continue;
                }
                keep.push(r.clone());
            }
            keep
        }
        None => Vec::new(),
    };
    #[cfg(feature = "dmg")]
    {
        // A target with nowhere to put them must not lose them silently.
        // (`plst` is hdiutil's constant boilerplate, not content.)
        let can_hold = target == ImageKind::Udif && {
            #[cfg(feature = "dmg-write")]
            {
                opts.udif.format != crate::block::dmg::UdifFormat::Udrw
            }
            #[cfg(not(feature = "dmg-write"))]
            {
                false
            }
        };
        let content: Vec<&str> = carried
            .iter()
            .filter(|r| r.kind != "plst")
            .map(|r| r.kind.as_str())
            .collect();
        if !can_hold && !content.is_empty() {
            return Err(crate::Error::InvalidArgument(format!(
                "convert: the source carries UDIF resources ({}) that a {} target cannot hold; \
                 set ResourcePolicy::Drop (CLI: --drop-resources) to discard them",
                content.join(", "),
                target.name()
            )));
        }
    }

    let mut dev = open_source(src, opts.password.as_deref())?;
    let total = dev.total_size();

    #[allow(unused_mut)]
    let mut report = ConvertReport {
        source,
        target,
        bytes: total,
        dropped_resources: dropped,
        #[cfg(feature = "dmg-write")]
        udif: None,
    };

    match target {
        ImageKind::Udif => {
            #[cfg(feature = "dmg-write")]
            {
                use crate::block::dmg::{UdifFormat, write_udif};
                let mut wo = opts.udif.clone();
                #[cfg(feature = "dmg")]
                if let Some(info) = &src_info {
                    if opts.preserve_layout {
                        wo.layout = super::resize::layout_of(info, None)?;
                        if let crate::block::dmg::UdifLayout::WholeDevice = wo.layout
                            && let Some(b) = info.blkx.first()
                            && !b.name.is_empty()
                        {
                            wo.partition_name = b.name.clone();
                        }
                    }
                    if wo.format != UdifFormat::Udrw {
                        let mut res = wo.resources.clone();
                        for r in &carried {
                            if res.get(&r.kind, r.id).is_none() {
                                res.entries.push(r.clone());
                            }
                        }
                        wo.resources = res;
                    }
                }
                wo.validate()?;
                let summary = write_beside(dst, |tmp| {
                    let f = std::fs::File::create(tmp)?;
                    let (f, summary) = write_udif(dev.as_mut(), f, &wo)?;
                    f.sync_all()?;
                    Ok(summary)
                })?;
                report.udif = Some(summary);
            }
            #[cfg(not(feature = "dmg-write"))]
            return Err(crate::Error::Unsupported(
                "convert: writing UDIF needs the `dmg-write` feature".into(),
            ));
        }
        ImageKind::Raw | ImageKind::SparseImage | ImageKind::SparseBundle | ImageKind::Qcow2 => {
            let co = crate::block::CreateOpts {
                sparse_band_size: opts.sparse_band_size,
                ..Default::default()
            };
            write_beside(dst, |tmp| {
                let mut out = crate::block::create_image(tmp, total, &co)?;
                copy_sectors(dev.as_mut(), out.as_mut(), total)?;
                out.sync()?;
                Ok(())
            })?;
        }
        ImageKind::Other => {
            return Err(crate::Error::InvalidArgument(
                "convert: ImageKind::Other is not a conversion target".into(),
            ));
        }
    }
    Ok(report)
}

/// Copy `total` bytes from `src` to the fresh, all-zero `dst`, skipping
/// all-zero pieces so sparse targets stay sparse.
pub(crate) fn copy_sectors(
    src: &mut dyn BlockDevice,
    dst: &mut dyn BlockDevice,
    total: u64,
) -> Result<()> {
    let mut buf = vec![0u8; COPY_CHUNK];
    let mut off = 0u64;
    while off < total {
        let n = (total - off).min(buf.len() as u64) as usize;
        src.read_at(off, &mut buf[..n])?;
        if buf[..n].iter().any(|&b| b != 0) {
            dst.write_at(off, &buf[..n])?;
        }
        off += n as u64;
    }
    Ok(())
}
