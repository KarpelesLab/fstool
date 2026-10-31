//! Container-only resizing.
//!
//! [`resize_container`] changes how many sectors an image *file* holds —
//! and nothing else. It does **not** resize the filesystem inside, and it
//! does **not** edit a partition table: grown space is unallocated zeros
//! past whatever was there, and a shrink only ever drops sectors that are
//! all zero (or free space) unless told to discard data. To grow or
//! shrink the filesystem as well, resize it with its own tool afterwards
//! (or before a shrink).

use std::path::Path;

use crate::Result;

/// What a container shrink may do with non-zero sectors past the new end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ShrinkData {
    /// Refuse — changing nothing — if any byte past the new end is
    /// non-zero. (Free space in a UDIF image reads as zeros.)
    #[default]
    RequireZero,
    /// Drop whatever lies past the new end. A filesystem or a backup
    /// partition table living there is truncated.
    Discard,
}

/// Options for [`resize_container`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ContainerResizeOptions {
    /// Non-zero data past a shrunken end. Default
    /// [`ShrinkData::RequireZero`].
    pub shrink: ShrinkData,
    /// For a UDIF image: the writer options of the rewritten image.
    /// `None` keeps the source's format (by its chunk codec), checksum
    /// type, segment ID and resources; its `blkx` map is kept too, with a
    /// grown tail recorded as one free-space entry and a shrunken one
    /// clipped. A format this build cannot write needs an override.
    #[cfg(feature = "dmg-write")]
    pub udif: Option<crate::block::dmg::UdifWriteOptions>,
    /// What a UDIF rewrite may drop (code signature, legacy resource
    /// fork). Default: refuse.
    #[cfg(feature = "dmg")]
    pub policy: crate::block::dmg::UdifRewritePolicy,
}

/// What [`resize_container`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContainerResizeReport {
    /// The image's kind.
    pub kind: super::ImageKind,
    /// Virtual size before, in bytes.
    pub old_size: u64,
    /// Virtual size after, in bytes.
    pub new_size: u64,
    /// Whether non-zero bytes past the new end were discarded.
    pub discarded_data: bool,
}

/// Resize the **container** at `path` to `new_size` bytes (a non-zero
/// multiple of 512) — raw file, `.sparseimage`, `.sparsebundle` or a
/// single-file UDIF image. The filesystem and the partition table inside
/// are *not* changed (see the module docs).
///
/// - **Grow** appends zero sectors.
/// - **Shrink** drops the tail; it is refused when the tail holds
///   non-zero data unless `opts.shrink` is [`ShrinkData::Discard`].
///
/// A raw or sparse image is resized in place, after every check passes; a
/// UDIF image is re-encoded beside itself and renamed over the original
/// on success. Either way a failure leaves the image as it was.
pub fn resize_container(
    path: &Path,
    new_size: u64,
    opts: &ContainerResizeOptions,
) -> Result<ContainerResizeReport> {
    if new_size == 0 || !new_size.is_multiple_of(512) {
        return Err(crate::Error::InvalidArgument(format!(
            "resize: the new size {new_size} must be a non-zero multiple of 512 bytes"
        )));
    }
    let kind = super::ImageKind::detect(path)?;
    match kind {
        super::ImageKind::Raw => resize_raw(path, new_size, opts.shrink),
        #[cfg(feature = "sparse-image")]
        super::ImageKind::SparseImage | super::ImageKind::SparseBundle => {
            let mut dev = crate::block::sparse::SparseBackend::open(path)?;
            let old_size = dev.as_block_device().total_size();
            let policy = match opts.shrink {
                ShrinkData::RequireZero => crate::block::ShrinkPolicy::RequireZero,
                ShrinkData::Discard => crate::block::ShrinkPolicy::Discard,
            };
            let discarded = new_size < old_size
                && opts.shrink == ShrinkData::Discard
                && tail_has_data(dev.as_block_device(), new_size, old_size)?;
            dev.resize(new_size, policy).map_err(|e| match e {
                crate::Error::InvalidArgument(m) if m.contains("nonzero") => {
                    crate::Error::InvalidArgument(format!(
                        "{m} (ShrinkData::Discard / --discard drops it — and truncates any \
                         filesystem or partition table living there)"
                    ))
                }
                e => e,
            })?;
            dev.as_block_device().sync()?;
            Ok(ContainerResizeReport {
                kind,
                old_size,
                new_size,
                discarded_data: discarded,
            })
        }
        #[cfg(feature = "dmg-write")]
        super::ImageKind::Udif => resize_udif(path, new_size, opts),
        other => Err(crate::Error::Unsupported(format!(
            "resize: container resizing of a {} image is not supported{}",
            other.name(),
            if other == super::ImageKind::Udif {
                " (needs the `dmg-write` feature)"
            } else {
                ""
            }
        ))),
    }
}

/// Whether any byte of `[from, to)` is non-zero.
fn tail_has_data(dev: &mut dyn crate::block::BlockDevice, from: u64, to: u64) -> Result<bool> {
    let mut buf = vec![0u8; super::COPY_CHUNK];
    let mut off = from;
    while off < to {
        let n = (to - off).min(buf.len() as u64) as usize;
        dev.read_at(off, &mut buf[..n])?;
        if buf[..n].iter().any(|&b| b != 0) {
            return Ok(true);
        }
        off += n as u64;
    }
    Ok(false)
}

fn resize_raw(path: &Path, new_size: u64, shrink: ShrinkData) -> Result<ContainerResizeReport> {
    if crate::block::file::is_block_device(path) {
        return Err(crate::Error::InvalidArgument(
            "resize: a block device's size is not the container's to change".into(),
        ));
    }
    let old_size = std::fs::metadata(path)?.len();
    let mut discarded = false;
    if new_size < old_size {
        let mut dev = crate::block::FileBackend::open_read_only(path)?;
        if tail_has_data(&mut dev, new_size, old_size)? {
            if shrink == ShrinkData::RequireZero {
                return Err(crate::Error::InvalidArgument(format!(
                    "resize: {} holds nonzero data past {new_size} bytes; refusing to drop it \
                     (ShrinkData::Discard / --discard drops it — and truncates any filesystem \
                     or partition table living there)",
                    path.display()
                )));
            }
            discarded = true;
        }
    }
    let f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.set_len(new_size)?;
    f.sync_all()?;
    Ok(ContainerResizeReport {
        kind: super::ImageKind::Raw,
        old_size,
        new_size,
        discarded_data: discarded,
    })
}

/// The `blkx` layout of `info`, adjusted to `new_sectors` when given:
/// a grown tail becomes one free-space entry, a shrunken map is clipped.
#[cfg(feature = "dmg-write")]
pub(crate) fn layout_of(
    info: &crate::block::dmg::UdifInfo,
    new_sectors: Option<u64>,
) -> Result<crate::block::dmg::UdifLayout> {
    use crate::block::dmg::{UdifLayout, UdifMapEntry};
    let mut entries: Vec<&crate::block::dmg::BlkxEntry> = info.blkx.iter().collect();
    entries.sort_by_key(|b| b.first_sector);
    let whole_disk = entries.len() == 1
        && entries[0].first_sector == 0
        && entries[0].sector_count == info.sector_count
        && entries[0].descriptor == -2;
    if whole_disk {
        return Ok(UdifLayout::WholeDevice);
    }
    let mut map = Vec::with_capacity(entries.len() + 1);
    let mut next = 0u64;
    for (i, b) in entries.iter().enumerate() {
        if b.first_sector != next || b.sector_count == 0 {
            return Err(crate::Error::InvalidImage(format!(
                "dmg: the source's blkx entries do not tile the disk (entry {i} starts at \
                 sector {}, expected {next}); convert without preserving the layout",
                b.first_sector
            )));
        }
        let name = if b.name.is_empty() {
            format!("blkx {i}")
        } else {
            b.name.clone()
        };
        let mut e = UdifMapEntry::new(name, b.first_sector, b.sector_count);
        e.id = b.id;
        e.descriptor = b.descriptor;
        e.free_space = b.is_free_space() || b.name.contains("(Apple_Free");
        map.push(e);
        next += b.sector_count;
    }
    if next != info.sector_count {
        return Err(crate::Error::InvalidImage(format!(
            "dmg: the source's blkx entries cover {next} sectors, the image {}",
            info.sector_count
        )));
    }
    if let Some(n) = new_sectors {
        if n > next {
            let (id, desc) = map
                .last()
                .map_or((0, 0), |e: &UdifMapEntry| (e.id + 1, e.descriptor + 1));
            let mut e = UdifMapEntry::new(format!(" (Apple_Free : {desc})"), next, n - next);
            e.id = id;
            e.descriptor = desc;
            e.free_space = true;
            map.push(e);
        } else {
            map.retain(|e| e.start_sector < n);
            if let Some(last) = map.last_mut() {
                last.sector_count = n - last.start_sector;
            }
        }
    }
    Ok(UdifLayout::Map(map))
}

#[cfg(feature = "dmg-write")]
fn resize_udif(
    path: &Path,
    new_size: u64,
    opts: &ContainerResizeOptions,
) -> Result<ContainerResizeReport> {
    use crate::block::BlockDevice;
    use crate::block::dmg::{
        BLKX_RESOURCE, DmgBackend, UdifChecksum, UdifFormat, UdifLayout, UdifWriteOptions,
        UdifWriter,
    };
    let mut dev = DmgBackend::open(path)?;
    let info = dev.info().clone();
    opts.policy.check(&info, "resizing")?;
    if info.is_segmented() {
        return Err(crate::Error::Unsupported(
            "resize: a segmented image must be joined before it is resized".into(),
        ));
    }
    let old_size = dev.total_size();
    let new_sectors = new_size / 512;
    let wo = match &opts.udif {
        Some(o) => o.clone(),
        None => {
            let format = UdifFormat::from_name(info.format_hint()).unwrap_or(UdifFormat::Udro);
            let checksum = match info.master_checksum.kind {
                0 => UdifChecksum::None,
                4 => UdifChecksum::Md5,
                _ => UdifChecksum::Crc32,
            };
            let mut res = info.resources.clone();
            res.entries
                .retain(|r| r.kind != BLKX_RESOURCE && r.kind != "cSum");
            let layout = layout_of(&info, Some(new_sectors))?;
            let partition_name = match (&layout, info.blkx.first()) {
                (UdifLayout::WholeDevice, Some(b)) if !b.name.is_empty() => b.name.clone(),
                _ => UdifWriteOptions::default().partition_name,
            };
            UdifWriteOptions {
                format,
                checksum,
                layout,
                partition_name,
                segment_id: Some(info.trailer().segment_id),
                resources: res,
                ..Default::default()
            }
        }
    };
    wo.validate()?;
    let mut discarded = false;
    if new_size < old_size && tail_has_data(&mut dev, new_size, old_size)? {
        if opts.shrink == ShrinkData::RequireZero {
            return Err(crate::Error::InvalidArgument(format!(
                "resize: {} holds nonzero data past {new_size} bytes; refusing to drop it \
                 (ShrinkData::Discard / --discard drops it — and truncates any filesystem or \
                 partition table living there)",
                path.display()
            )));
        }
        discarded = true;
    }
    // Build beside the image, close the source, then rename over it (the
    // source must be closed first for the rename to succeed on Windows).
    let tmp = super::temp_sibling(path, "resize")?;
    let built = (|| -> Result<()> {
        let f = std::fs::File::create(&tmp)?;
        let mut w = UdifWriter::new(f, &wo)?;
        let mut buf = vec![0u8; wo.chunk_sectors as usize * 512];
        let keep = old_size.min(new_size);
        let mut off = 0u64;
        while off < new_size {
            let n = (new_size - off).min(buf.len() as u64) as usize;
            if off < keep {
                let m = ((keep - off) as usize).min(n);
                dev.read_at(off, &mut buf[..m])?;
                buf[m..n].fill(0);
            } else {
                buf[..n].fill(0);
            }
            w.write_sectors(&buf[..n])?;
            off += n as u64;
        }
        let (f, _) = w.finish()?;
        f.sync_all()?;
        Ok(())
    })();
    drop(dev);
    if let Err(e) = built.and_then(|()| super::publish(&tmp, path)) {
        let _ = super::remove_any(&tmp);
        return Err(e);
    }
    Ok(ContainerResizeReport {
        kind: super::ImageKind::Udif,
        old_size,
        new_size,
        discarded_data: discarded,
    })
}
