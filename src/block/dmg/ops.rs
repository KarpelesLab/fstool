//! UDIF editing that keeps the chunk data as stored: segmenting and
//! joining, editing the resource map, removing a code signature.
//!
//! None of these decode or re-encode a chunk — the data fork is copied
//! byte for byte, so the partition and master checksums stay valid — and
//! all of them write beside the destination and rename on success, so a
//! failure leaves any existing output as it was.
//!
//! Re-encoding operations (format conversion, container resize) are in
//! [`crate::block::imageops`].

use std::fs::File;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::container::{Container, MAX_SEGMENTS, StoredChecksum, udif_segment_path};
use super::policy::UdifRewritePolicy;
use super::pvalue::{self, Value};
use super::resources::{BLKX_RESOURCE, UdifResources, check_kind};
use super::{KOLY_SIZE, KolyTrailer};
use crate::Result;
use crate::block::imageops::{COPY_CHUNK, ChecksumHasher, remove_any, same_file, temp_sibling};

/// The plist `hdiutil segment` writes into every segment after the
/// first: an empty resource map.
const EMPTY_SEGMENT_PLIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\t<key>resource-fork</key>\n\t<dict/>\n</dict>\n</plist>\n";

/// A data-fork checksum to compute: the type of `like`, or none.
fn fork_hasher(like: &StoredChecksum, what: &str) -> Result<Option<ChecksumHasher>> {
    if like.is_none() {
        return Ok(None);
    }
    match like.algorithm() {
        Some(a) => Ok(Some(ChecksumHasher::new(a))),
        None => Err(crate::Error::Unsupported(format!(
            "dmg: the source's data-fork checksum is of type {}, which fstool cannot compute \
             for {what}",
            like.kind
        ))),
    }
}

/// Turn a finished hasher into the trailer's checksum fields.
fn set_data_checksum(t: &mut KolyTrailer, sum: Option<ChecksumHasher>) {
    let (kind, bits, data) = match sum {
        None => (0, 0, [0u8; 128]),
        Some(h) => {
            let alg = h.algorithm();
            let v = h.finish();
            let mut d = [0u8; 128];
            d[..v.len()].copy_from_slice(&v);
            (alg.udif_type(), alg.bits(), d)
        }
    };
    t.data_checksum_type = kind;
    t.data_checksum_size = bits;
    t.data_checksum = data;
}

/// Copy `len` bytes of the logical data fork from `start` to `out`,
/// feeding `sum`.
fn copy_fork(
    c: &mut Container,
    start: u64,
    len: u64,
    out: &mut impl Write,
    mut sum: Option<&mut ChecksumHasher>,
) -> Result<()> {
    let mut buf = vec![0u8; COPY_CHUNK];
    let mut done = 0u64;
    while done < len {
        let n = (len - done).min(buf.len() as u64) as usize;
        c.read_fork(start + done, &mut buf[..n])?;
        out.write_all(&buf[..n])?;
        if let Some(s) = sum.as_deref_mut() {
            s.update(&buf[..n]);
        }
        done += n as u64;
    }
    Ok(())
}

/// The original plist bytes of the first segment.
fn original_plist(c: &mut Container) -> Result<Vec<u8>> {
    let t = c.info.trailer().clone();
    let src = c.segs[0].src.as_mut();
    src.seek(SeekFrom::Start(t.xml_offset))?;
    let mut b = vec![0u8; t.xml_length as usize];
    src.read_exact(&mut b)?;
    Ok(b)
}

/// The trailer of a single-file rewrite of `c`: the source's, with the
/// layout fields reset. Code-signature fields are never carried (the
/// trailer encoder does not write them), nor is a legacy resource fork.
fn rewrite_trailer(c: &Container, fork_len: u64, plist_len: u64) -> KolyTrailer {
    let mut t = c.info.trailer().clone();
    t.running_data_fork_offset = 0;
    t.data_fork_offset = 0;
    t.data_fork_length = fork_len;
    t.rsrc_fork_offset = 0;
    t.rsrc_fork_length = 0;
    t.xml_offset = fork_len;
    t.xml_length = plist_len;
    t
}

/// Write `c` as one file at `path`: its whole data fork, `plist`, and a
/// trailer. With `recompute` the data-fork checksum is recomputed over
/// the whole fork (of the first segment's type); otherwise the first
/// segment's is kept (valid only when the fork is that segment's).
fn write_single(
    c: &mut Container,
    path: &Path,
    plist: &[u8],
    recompute: bool,
) -> Result<KolyTrailer> {
    let fork_len = c.info.fork_length;
    let mut t = rewrite_trailer(c, fork_len, plist.len() as u64);
    let mut out = BufWriter::new(File::create(path)?);
    if recompute {
        let mut sum = fork_hasher(&c.info.segments[0].data_checksum(), "the joined image")?;
        // Validate every segment's own checksum on the way through.
        let segs: Vec<_> = c.info.segments.clone();
        for s in &segs {
            let stored = s.data_checksum();
            let mut own = match stored.algorithm() {
                Some(a) if !stored.is_none() => Some(ChecksumHasher::new(a)),
                _ => None,
            };
            let mut buf = vec![0u8; COPY_CHUNK];
            let (start, len) = (s.fork_start(), s.trailer.data_fork_length);
            let mut done = 0u64;
            while done < len {
                let n = (len - done).min(buf.len() as u64) as usize;
                c.read_fork(start + done, &mut buf[..n])?;
                out.write_all(&buf[..n])?;
                if let Some(h) = sum.as_mut() {
                    h.update(&buf[..n]);
                }
                if let Some(h) = own.as_mut() {
                    h.update(&buf[..n]);
                }
                done += n as u64;
            }
            if let Some(h) = own
                && h.finish() != stored.value()
            {
                return Err(crate::Error::InvalidImage(format!(
                    "dmg: segment {} fails its data-fork checksum",
                    s.path
                        .as_ref()
                        .map_or_else(|| "?".to_string(), |p| p.display().to_string())
                )));
            }
        }
        set_data_checksum(&mut t, sum);
    } else {
        copy_fork(c, 0, fork_len, &mut out, None)?;
    }
    out.write_all(plist)?;
    out.write_all(&t.encode())?;
    let f = out.into_inner().map_err(|e| e.into_error())?;
    f.sync_all()?;
    Ok(t)
}

/// Build the output in a temp sibling of `dst` from `c`, close the
/// source, and rename the output over `dst` on success (the source must be
/// closed first for an in-place rewrite to rename on Windows). On failure
/// the temp file is removed and `dst` is untouched.
fn write_file_beside<T>(
    mut c: Container,
    dst: &Path,
    build: impl FnOnce(&mut Container, &Path) -> Result<T>,
) -> Result<T> {
    let tmp = temp_sibling(dst, "new")?;
    let _ = remove_any(&tmp);
    let r = build(&mut c, &tmp);
    drop(c);
    let r = r.and_then(|v| crate::block::imageops::publish(&tmp, dst).map(|()| v));
    if r.is_err() {
        let _ = remove_any(&tmp);
    }
    r
}

// ---------------------------------------------------------------------
// Code signature
// ---------------------------------------------------------------------

/// Write `src` to `dst` without its code signature. Everything else —
/// data fork, plist, checksums — is kept byte for byte. `dst` may be
/// `src` (rewritten in place, safely). A segmented image is refused;
/// an unsigned one is copied unchanged.
pub fn remove_code_signature(src: &Path, dst: &Path) -> Result<()> {
    let mut c = Container::open(src)?;
    if c.info.is_segmented() {
        return Err(crate::Error::Unsupported(
            "dmg: removing a signature from a segmented image is not supported; join it first"
                .into(),
        ));
    }
    let policy = UdifRewritePolicy {
        signature: super::SignaturePolicy::Remove,
        ..UdifRewritePolicy::default()
    };
    policy.check(&c.info, "removing the signature")?;
    let plist = original_plist(&mut c)?;
    write_file_beside(c, dst, |c, tmp| {
        write_single(c, tmp, &plist, false).map(|_| ())
    })
}

// ---------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------

/// Changes to an image's resource map, applied in field order:
/// `replace_all`, then `remove`, then `add`.
///
/// `blkx` (the chunk tables) is protected: naming it in `remove` or `add`
/// is refused, and `replace_all` keeps it.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ResourceEdit {
    /// Remove every resource except `blkx` first (as
    /// `hdiutil udifrez -replaceall`).
    pub replace_all: bool,
    /// Resources to remove: a type, and an ID (`None`: every resource of
    /// the type).
    pub remove: Vec<(String, Option<i32>)>,
    /// Resources to add; one with the type and ID of an existing resource
    /// replaces it.
    pub add: UdifResources,
    /// What the rewrite may drop.
    pub policy: UdifRewritePolicy,
}

/// Apply `edit` to the resource map of the UDIF image `src`, writing the
/// result to `dst` (which may be `src`; for a segmented image it must be,
/// and only the first segment is rewritten). Returns the new map.
///
/// The data fork is copied unchanged, so every checksum stays valid; the
/// plist is re-serialised with its other top-level keys kept. The image
/// must have a fully parsed plist ([`super::UdifInfo::resources_complete`]).
pub fn edit_udif_resources(src: &Path, dst: &Path, edit: &ResourceEdit) -> Result<UdifResources> {
    for (k, _) in &edit.remove {
        if k == BLKX_RESOURCE {
            return Err(crate::Error::InvalidArgument(
                "dmg: blkx describes the image's data and cannot be removed".into(),
            ));
        }
    }
    for r in &edit.add.entries {
        check_kind(&r.kind)?;
        if r.kind == BLKX_RESOURCE {
            return Err(crate::Error::InvalidArgument(
                "dmg: blkx describes the image's data and cannot be added or replaced".into(),
            ));
        }
    }
    let c = Container::open(src)?;
    edit.policy.check(&c.info, "editing its resources")?;
    if !c.info.resources_complete {
        return Err(crate::Error::Unsupported(
            "dmg: the image's resource plist could not be fully parsed; refusing to rewrite it"
                .into(),
        ));
    }
    if c.info.is_segmented() && !same_file(src, dst) {
        return Err(crate::Error::Unsupported(
            "dmg: a segmented image's resources can only be edited in place".into(),
        ));
    }
    let mut res = c.info.resources.clone();
    if edit.replace_all {
        res.entries.retain(|r| r.kind == BLKX_RESOURCE);
    }
    for (k, id) in &edit.remove {
        res.remove(k, *id);
    }
    for r in &edit.add.entries {
        res.insert(r.clone());
    }
    let mut root = c.info.plist_root.clone().unwrap_or(Value::Dict(Vec::new()));
    if let Value::Dict(entries) = &mut root {
        match entries.iter_mut().find(|(k, _)| k == "resource-fork") {
            Some((_, v)) => *v = res.to_value(),
            None => entries.push(("resource-fork".into(), res.to_value())),
        }
    }
    let plist = pvalue::write_document(&root);
    if c.info.is_segmented() {
        // Only the first file holds the plist; its data slice stays as is.
        let len = c.segs[0].len;
        let mut t = c.info.trailer().clone();
        t.data_fork_offset = 0;
        t.data_fork_length = len;
        t.rsrc_fork_offset = 0;
        t.rsrc_fork_length = 0;
        t.xml_offset = len;
        t.xml_length = plist.len() as u64;
        write_file_beside(c, dst, |c, tmp| {
            let mut out = BufWriter::new(File::create(tmp)?);
            copy_fork(c, 0, len, &mut out, None)?;
            out.write_all(plist.as_bytes())?;
            out.write_all(&t.encode())?;
            out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
            Ok(())
        })?;
    } else {
        write_file_beside(c, dst, |c, tmp| {
            write_single(c, tmp, plist.as_bytes(), false).map(|_| ())
        })?;
    }
    Ok(res)
}

// ---------------------------------------------------------------------
// Segmenting
// ---------------------------------------------------------------------

/// Options for [`segment_udif`]. Set `segment_size` or `segment_count`.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SegmentOptions {
    /// Data-fork bytes per segment (`hdiutil segment -segmentSize`). The
    /// last segment holds the remainder. 0 = use `segment_count`.
    pub segment_size: u64,
    /// Split into this many segments of (nearly) equal size
    /// (`-segmentCount`). Used when `segment_size` is 0.
    pub segment_count: Option<u32>,
    /// Data-fork bytes in the first segment, when it should differ
    /// (`-firstSegmentSize`).
    pub first_segment_size: Option<u64>,
    /// The set's 16-byte segment ID; `None` draws a random UUID.
    pub segment_id: Option<[u8; 16]>,
    /// Replace existing output files (and remove stale `.dmgpart`s of the
    /// set being replaced). Off: any existing output is an error.
    pub overwrite: bool,
    /// What the rewrite may drop.
    pub policy: UdifRewritePolicy,
}

/// What [`segment_udif`] wrote.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SegmentReport {
    /// The segment files, first to last.
    pub paths: Vec<PathBuf>,
    /// The set's segment ID.
    pub segment_id: [u8; 16],
    /// Data-fork bytes in each segment.
    pub fork_lengths: Vec<u64>,
}

/// Split the UDIF image `src` into a segment set whose first file is
/// `dst` (`out.dmg`, then `out.002.dmgpart`, … — see
/// [`udif_segment_path`]), as `hdiutil segment` does.
///
/// The data fork is cut into slices; the first segment carries the full
/// resource plist, the others an empty one. Every trailer records the
/// segment number and count, the set's ID, its slice's offset in the
/// logical data fork and a data-fork checksum over its own slice (of the
/// source's data-checksum type; none if the source has none). The master
/// checksum and sector count are copied. `src` may itself be segmented.
pub fn segment_udif(src: &Path, dst: &Path, opts: &SegmentOptions) -> Result<SegmentReport> {
    let mut c = Container::open(src)?;
    opts.policy.check(&c.info, "segmenting")?;
    let fork = c.info.fork_length;
    // Slice boundaries.
    let mut sizes = Vec::new();
    if opts.segment_size > 0 {
        let first = opts.first_segment_size.unwrap_or(opts.segment_size);
        if first == 0 {
            return Err(crate::Error::InvalidArgument(
                "dmg: first_segment_size must be non-zero".into(),
            ));
        }
        let mut left = fork;
        let mut next = first;
        loop {
            let n = left.min(next);
            sizes.push(n);
            left -= n;
            next = opts.segment_size;
            if left == 0 || sizes.len() > MAX_SEGMENTS as usize {
                break;
            }
        }
    } else if let Some(count) = opts.segment_count {
        if count == 0 {
            return Err(crate::Error::InvalidArgument(
                "dmg: segment_count must be at least 1".into(),
            ));
        }
        let count = u64::from(count).min(fork.max(1));
        let each = fork.div_ceil(count);
        let mut left = fork;
        for _ in 0..count {
            let n = left.min(each);
            sizes.push(n);
            left -= n;
        }
        while sizes.len() > 1 && sizes.last() == Some(&0) {
            sizes.pop();
        }
    } else {
        return Err(crate::Error::InvalidArgument(
            "dmg: set SegmentOptions::segment_size or segment_count".into(),
        ));
    }
    if sizes.len() > MAX_SEGMENTS as usize {
        return Err(crate::Error::InvalidArgument(format!(
            "dmg: that would make more than {MAX_SEGMENTS} segments"
        )));
    }
    let count = sizes.len() as u32;
    let paths: Vec<PathBuf> = (1..=count).map(|n| udif_segment_path(dst, n)).collect();
    for p in &paths {
        let clashes_with_source = c
            .info
            .segments
            .iter()
            .filter_map(|s| s.path.as_deref())
            .any(|s| same_file(s, p));
        if clashes_with_source {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: output {} is part of the source image",
                p.display()
            )));
        }
        if !opts.overwrite && p.exists() {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: {} already exists (set overwrite to replace it)",
                p.display()
            )));
        }
    }
    // The set being replaced, so its surplus parts can be removed after.
    let old_set = if opts.overwrite && dst.is_file() {
        super::inspect_udif(dst)
            .ok()
            .map(|i| (i.trailer().segment_id, i.trailer().segment_count))
    } else {
        None
    };

    let template = c.info.trailer().clone();
    let like = c.info.segments[0].data_checksum();
    let segment_id = opts
        .segment_id
        .unwrap_or_else(|| *uuid::Uuid::new_v4().as_bytes());
    let plist0 = original_plist(&mut c)?;
    let tmps: Vec<PathBuf> = paths
        .iter()
        .map(|p| temp_sibling(p, "seg"))
        .collect::<Result<_>>()?;
    let result = (|| -> Result<()> {
        let mut start = 0u64;
        for (i, (&len, tmp)) in sizes.iter().zip(&tmps).enumerate() {
            let plist = if i == 0 {
                plist0.as_slice()
            } else {
                EMPTY_SEGMENT_PLIST.as_bytes()
            };
            let mut t = template.clone();
            t.running_data_fork_offset = start;
            t.data_fork_offset = 0;
            t.data_fork_length = len;
            t.rsrc_fork_offset = 0;
            t.rsrc_fork_length = 0;
            t.xml_offset = len;
            t.xml_length = plist.len() as u64;
            t.segment_number = i as u32 + 1;
            t.segment_count = count;
            t.segment_id = segment_id;
            let mut sum = fork_hasher(&like, "the segments")?;
            let mut out = BufWriter::new(File::create(tmp)?);
            copy_fork(&mut c, start, len, &mut out, sum.as_mut())?;
            set_data_checksum(&mut t, sum);
            out.write_all(plist)?;
            out.write_all(&t.encode())?;
            out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
            start += len;
        }
        Ok(())
    })();
    if let Err(e) = result {
        for t in &tmps {
            let _ = remove_any(t);
        }
        return Err(e);
    }
    // Publish the parts before the first file, so a reader that opens the
    // first file never finds parts of an older set.
    for (tmp, p) in tmps.iter().zip(&paths).rev() {
        std::fs::rename(tmp, p)?;
    }
    if let Some((old_id, old_count)) = old_set {
        for n in count + 1..=old_count.min(MAX_SEGMENTS) {
            let p = udif_segment_path(dst, n);
            let ours = read_segment_id(&p).is_some_and(|id| id == old_id);
            if ours {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    Ok(SegmentReport {
        paths,
        segment_id,
        fork_lengths: sizes,
    })
}

fn read_segment_id(p: &Path) -> Option<[u8; 16]> {
    use std::io::Read;
    let mut f = File::open(p).ok()?;
    let len = f.metadata().ok()?.len();
    if len < KOLY_SIZE {
        return None;
    }
    f.seek(SeekFrom::Start(len - KOLY_SIZE)).ok()?;
    let mut raw = [0u8; KOLY_SIZE as usize];
    f.read_exact(&mut raw).ok()?;
    KolyTrailer::decode(&raw).ok().map(|t| t.segment_id)
}

/// Options for [`join_udif`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct JoinOptions {
    /// What the rewrite may drop.
    pub policy: UdifRewritePolicy,
}

/// Join the segment set whose first file is `src` into the single-file
/// image `dst`.
///
/// Opening the set validates it (every segment present, same segment ID,
/// count and sector count, consecutive numbers, contiguous data-fork
/// ranges); while copying, each segment's data-fork checksum is
/// recomputed and a mismatch aborts the join. The output's data-fork
/// checksum is computed over the whole fork (of the segments' type), the
/// master checksum and the `blkx` tables are kept.
pub fn join_udif(src: &Path, dst: &Path, opts: &JoinOptions) -> Result<KolyTrailer> {
    let mut c = Container::open(src)?;
    opts.policy.check(&c.info, "joining")?;
    for s in &c.info.segments {
        if let Some(p) = &s.path
            && same_file(p, dst)
        {
            return Err(crate::Error::InvalidArgument(format!(
                "dmg: the joined output {} would overwrite a segment of the source",
                dst.display()
            )));
        }
    }
    let plist = original_plist(&mut c)?;
    write_file_beside(c, dst, |c, tmp| {
        let mut t = write_single(c, tmp, &plist, true)?;
        // Mark it a one-segment image; rewrite the trailer in place.
        t.segment_number = 1;
        t.segment_count = 1;
        let mut f = std::fs::OpenOptions::new().write(true).open(tmp)?;
        let len = f.metadata()?.len();
        f.seek(SeekFrom::Start(len - KOLY_SIZE))?;
        f.write_all(&t.encode())?;
        f.sync_all()?;
        Ok(t)
    })
}
