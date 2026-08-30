//! qcow2 — QEMU's copy-on-write disk format, as a [`BlockDevice`].
//!
//! Supports reading and writing v2 and v3 images, including compressed
//! clusters, backing files, and (behind the `qcow2-crypto` feature)
//! encrypted images. Snapshots, external data files and extended L2
//! entries error with [`crate::Error::Unsupported`] on open.
//!
//! ## Layout
//!
//! A qcow2 file is a sequence of fixed-size clusters (typically 64 KiB).
//! The first cluster carries the header. From there, three sets of
//! metadata clusters live alongside data clusters:
//!
//! - **Refcount table** (one or more clusters, pointed at by
//!   `refcount_table_offset`): array of u64 entries pointing to refcount
//!   *blocks*.
//! - **Refcount blocks**: array of u16 refcounts, one per data/metadata
//!   cluster. Used to find free clusters when allocating.
//! - **L1 table** (`l1_table_offset`): array of u64 entries pointing to
//!   **L2 tables**, which in turn point to data clusters.
//!
//! `total_size()` returns the virtual size from the header; storage is
//! allocate-on-write, so a freshly-created 100 GiB image is only a few
//! clusters on disk until you write to it.
//!
//! ## Backing files
//!
//! An image may name a *backing file*: a second image supplying every
//! cluster this one has not allocated. That is how `qemu-img create -b`
//! makes a thin overlay over a golden base — the overlay starts empty and
//! grows only with what is written to it.
//!
//! Reads consult the backing chain for unallocated clusters; a cluster
//! carrying the ZERO flag reads as zeros and stops the search. Writes
//! copy the whole cluster up from the backing file before applying the
//! new bytes, because a qcow2 cluster is all-or-nothing: once allocated,
//! it shadows the backing file completely. The backing image is always
//! opened read-only, and [`MAX_BACKING_DEPTH`] bounds how far a chain
//! (or a cycle) can be followed.
//!
//! ## Concurrency
//!
//! qcow2 is not safe to share between writers. `Qcow2Backend` holds the
//! file open `O_RDWR` without an exclusive lock — the caller is expected
//! to not have another writer pointed at the same file.

pub mod compress;
pub mod header;
pub mod l1l2;
pub mod refcount;

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use header::Header;
use l1l2::{COPIED, L1L2, Mapping, ZERO};
use refcount::Refcount;

use super::BlockDevice;
use crate::Result;

/// How many images deep a backing chain may go before we refuse.
///
/// Bounds both a legitimately silly chain and a malicious cycle (an image
/// naming itself, or two naming each other), which would otherwise recurse
/// until the stack ran out.
pub const MAX_BACKING_DEPTH: usize = 32;

/// A [`BlockDevice`] backed by a qcow2 image.
pub struct Qcow2Backend {
    file: File,
    header: Header,
    cluster_size: u64,
    l1l2: L1L2,
    refcount: Refcount,
    /// Current backing-file size in bytes; grows when allocate-on-write
    /// extends the file past the previous EOF.
    file_len: u64,
    /// Virtual cursor for the `Read`/`Write`/`Seek` impls.
    cursor: u64,
    /// Single-entry cache of the most recently decompressed cluster, keyed by
    /// its virtual cluster-start offset, so sequential sub-cluster reads of a
    /// compressed cluster don't re-inflate it.
    decomp_cache: Option<(u64, Vec<u8>)>,
    /// True when the backing `File` was opened `O_RDONLY` by
    /// [`Self::open_read_only`]. Writes return `PermissionDenied`
    /// early so callers get a clean refusal rather than a deep
    /// syscall-level error.
    read_only: bool,
    /// The opened backing image, when the header names one. Always
    /// read-only; unallocated clusters read through to it.
    backing: Option<Box<dyn BlockDevice>>,
    /// The backing filename exactly as the header spells it (which may be
    /// relative to this image's directory).
    backing_file: Option<String>,
    /// The backing file's format, from the `BACKING_FORMAT` header
    /// extension. `None` means the header didn't say and we probed.
    backing_format: Option<String>,
}

impl std::fmt::Debug for Qcow2Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Qcow2Backend")
            .field("version", &self.header.version)
            .field("cluster_size", &self.cluster_size)
            .field("virtual_size", &self.header.size)
            .field("l1_size", &self.header.l1_size)
            .field("backing_file", &self.backing_file)
            .finish()
    }
}

impl Qcow2Backend {
    /// Open an existing qcow2 file read+write. Errors with `Unsupported`
    /// if the image uses features fstool doesn't implement.
    ///
    /// A backing file named in the header is resolved relative to this
    /// image's directory and opened read-only.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_inner(path.as_ref(), false, 0)
    }

    /// Open an existing qcow2 file read-only. The backing `File` is
    /// opened `O_RDONLY` — any write that slips past the BlockDevice
    /// API would fail at the syscall. The qcow2 read paths
    /// (L1/L2/refcount load, cluster reads) work unchanged.
    pub fn open_read_only<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_inner(path.as_ref(), true, 0)
    }

    fn open_inner(path: &Path, read_only: bool, depth: usize) -> Result<Self> {
        if depth > MAX_BACKING_DEPTH {
            return Err(crate::Error::InvalidImage(format!(
                "qcow2: backing chain deeper than {MAX_BACKING_DEPTH} images \
                 (a loop, or a chain that long)"
            )));
        }
        let mut opts = OpenOptions::new();
        opts.read(true);
        if !read_only {
            opts.write(true);
        }
        let mut file = opts.open(path)?;
        let (header, head) = Self::read_header(&mut file)?;
        let cluster_size = header.cluster_size();

        let backing_file = Self::backing_name(&header, &head)?;
        let backing_format = header
            .extensions
            .iter()
            .find(|e| e.kind == header::ext_type::BACKING_FORMAT)
            .and_then(|e| e.as_str())
            .map(|s| s.trim_end_matches('\0').to_owned());
        let backing = match &backing_file {
            Some(name) => Some(Self::open_backing(
                path,
                name,
                backing_format.as_deref(),
                depth,
            )?),
            None => None,
        };

        let l1l2 = L1L2::load(&mut file, &header)?;
        let refcount = Refcount::load(&mut file, &header)?;
        let file_len = file.metadata()?.len();
        Ok(Self {
            file,
            header,
            cluster_size,
            l1l2,
            refcount,
            file_len,
            cursor: 0,
            decomp_cache: None,
            read_only,
            backing,
            backing_file,
            backing_format,
        })
    }

    /// Read and decode the header, together with the bytes of the first
    /// cluster it lives in.
    ///
    /// Two passes: the first 512 bytes are enough to learn `cluster_bits`
    /// (and reach the `compression_type` byte at offset 104), and the
    /// header extensions plus the backing filename that follow can run to
    /// the end of that first cluster — so the second pass re-decodes over
    /// the whole cluster.
    fn read_header(file: &mut File) -> Result<(Header, Vec<u8>)> {
        let mut probe = [0u8; 512];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut probe)?;
        let first = Header::decode(&probe)?;
        let cluster_size = first.cluster_size() as usize;
        if cluster_size <= probe.len() {
            return Ok((first, probe.to_vec()));
        }
        let mut head = vec![0u8; cluster_size];
        file.seek(SeekFrom::Start(0))?;
        // A qcow2 file is always at least one cluster, but a truncated one
        // is not — fall back to the 512-byte view rather than failing, so
        // the more specific validation errors still get a chance to fire.
        match file.read_exact(&mut head) {
            Ok(()) => Ok((Header::decode(&head)?, head)),
            Err(_) => Ok((first, probe.to_vec())),
        }
    }

    /// Pull the backing filename out of the header cluster.
    fn backing_name(header: &Header, head: &[u8]) -> Result<Option<String>> {
        if header.backing_file_offset == 0 || header.backing_file_size == 0 {
            return Ok(None);
        }
        let start = header.backing_file_offset as usize;
        let len = header.backing_file_size as usize;
        // The spec caps the name at 1023 bytes and places it inside the
        // first cluster, so anything outside that is a malformed header.
        if len > 1023 || start.saturating_add(len) > head.len() {
            return Err(crate::Error::InvalidImage(format!(
                "qcow2: backing filename (offset {start}, {len} bytes) \
                 does not fit in the header cluster"
            )));
        }
        let name = std::str::from_utf8(&head[start..start + len]).map_err(|e| {
            crate::Error::InvalidImage(format!("qcow2: backing filename is not UTF-8: {e}"))
        })?;
        let name = name.trim_end_matches('\0');
        if name.is_empty() {
            return Ok(None);
        }
        Ok(Some(name.to_owned()))
    }

    /// Resolve `name` against `image`'s directory, the way qemu does:
    /// an absolute path is taken as-is, a relative one is relative to the
    /// *referring image*, not the process's working directory.
    pub fn resolve_backing_path(image: &Path, name: &str) -> std::path::PathBuf {
        let candidate = Path::new(name);
        if candidate.is_absolute() {
            return candidate.to_path_buf();
        }
        match image.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join(candidate),
            _ => candidate.to_path_buf(),
        }
    }

    /// Open the backing image read-only, honouring the declared format.
    fn open_backing(
        image: &Path,
        name: &str,
        format: Option<&str>,
        depth: usize,
    ) -> Result<Box<dyn BlockDevice>> {
        let path = Self::resolve_backing_path(image, name);
        if !path.exists() {
            return Err(crate::Error::InvalidImage(format!(
                "qcow2: backing file `{name}` not found (looked at {})",
                path.display()
            )));
        }
        match format {
            // An explicit format is authoritative — that is the whole
            // reason the extension exists. A raw backing file that happens
            // to start with qcow2 magic must still be read as raw.
            Some("qcow2") => Ok(Box::new(Self::open_inner(&path, true, depth + 1)?)),
            Some("raw") => Ok(Box::new(super::FileBackend::open_read_only(&path)?)),
            Some(other) => Err(crate::Error::Unsupported(format!(
                "qcow2: backing file `{name}` declares format `{other}`, \
                 which fstool does not open as a backing image"
            ))),
            // No declared format: probe, exactly as qemu does when the
            // extension is absent.
            None if Self::probe(&path)? => Ok(Box::new(Self::open_inner(&path, true, depth + 1)?)),
            None => Ok(super::open_image_read_only(&path)?),
        }
    }

    /// The backing filename as the header spells it, if any.
    pub fn backing_file(&self) -> Option<&str> {
        self.backing_file.as_deref()
    }

    /// The backing file's declared format, if the header said.
    pub fn backing_format(&self) -> Option<&str> {
        self.backing_format.as_deref()
    }

    /// Format a fresh qcow2 v3 image at `path`. The file is created
    /// (truncating any existing one) and seeded with the header, an
    /// empty refcount table + refcount block, and an L1 table. All
    /// data clusters are allocate-on-write.
    pub fn create<P: AsRef<Path>>(path: P, virtual_size: u64, cluster_size: u32) -> Result<Self> {
        Self::create_with_backing(path, virtual_size, cluster_size, None)
    }

    /// Format a fresh qcow2 v3 image that reads through to `backing`.
    ///
    /// `backing` is `(path, format)`: the path recorded in the header —
    /// relative paths are resolved against the new image's directory when
    /// it is later opened, so passing a relative one makes the pair
    /// movable together — and the format name to record in the
    /// `BACKING_FORMAT` extension (`"qcow2"`, `"raw"`, …). Pass `None` for
    /// the format to have it probed from the backing file itself, which is
    /// what `qemu-img create -b` without `-F` does; naming it explicitly
    /// is better, and is why `qemu-img` warns when you don't.
    ///
    /// `virtual_size` of 0 means "same as the backing file", matching
    /// `qemu-img create -b`'s default.
    pub fn create_with_backing<P: AsRef<Path>>(
        path: P,
        virtual_size: u64,
        cluster_size: u32,
        backing: Option<(&Path, Option<&str>)>,
    ) -> Result<Self> {
        let path = path.as_ref();
        // Resolve the backing file first: it settles the virtual size when
        // the caller left that to us, and a broken reference should fail
        // before we truncate anything.
        let backing_info = match backing {
            Some((name, format)) => {
                let name_str = name.to_str().ok_or_else(|| {
                    crate::Error::InvalidArgument(format!(
                        "qcow2: backing path {} is not valid UTF-8",
                        name.display()
                    ))
                })?;
                if name_str.len() > 1023 {
                    return Err(crate::Error::InvalidArgument(
                        "qcow2: backing filename exceeds the format's 1023-byte limit".into(),
                    ));
                }
                let dev = Self::open_backing(path, name_str, format, 0)?;
                Some((name_str.to_owned(), format.map(str::to_owned), dev))
            }
            None => None,
        };
        let virtual_size = match (virtual_size, &backing_info) {
            (0, Some((_, _, dev))) => dev.total_size(),
            (n, _) => n,
        };

        if !cluster_size.is_power_of_two() || cluster_size < 512 {
            return Err(crate::Error::InvalidArgument(format!(
                "qcow2: cluster_size {cluster_size} must be a power of two ≥ 512"
            )));
        }
        let cs = cluster_size as u64;
        let cluster_bits = cs.trailing_zeros();

        // Compute L1 size: one L2 cluster covers (cs/8) clusters, which
        // covers (cs/8) * cs virtual bytes. l1 entries needed:
        let l2_coverage = (cs / 8) * cs;
        let l1_size = virtual_size.div_ceil(l2_coverage) as u32;
        // L1 size must be a power of two? No — but it does need to fit
        // in some number of clusters. Round up `l1_size` to a multiple
        // of (cs / 8) so the L1 table is a whole number of clusters.
        let l1_per_cluster = (cs / 8) as u32;
        let l1_clusters = l1_size.div_ceil(l1_per_cluster);
        let l1_size = l1_clusters * l1_per_cluster;

        // Layout (in clusters):
        //   0:                header
        //   1:                refcount table (1 cluster)
        //   2:                refcount block 0
        //   3..3+l1_clusters: L1 table
        let refcount_table_cluster = 1u64;
        let refcount_block_cluster = 2u64;
        let l1_first_cluster = 3u64;
        let next_free_cluster = l1_first_cluster + l1_clusters as u64;
        let file_len = next_free_cluster * cs;

        // The clusters we just laid out must all have refcount=1.
        let initial: Vec<u64> = {
            let mut v = Vec::new();
            v.push(0); // header
            v.push(refcount_table_cluster);
            v.push(refcount_block_cluster);
            for i in 0..l1_clusters as u64 {
                v.push(l1_first_cluster + i);
            }
            v
        };

        // Lay out the header cluster: fixed header, then the extension
        // chain, then the backing filename right after it (where every
        // qcow2 writer puts it).
        let extensions: Vec<header::Extension> = match &backing_info {
            Some((_, Some(fmt), _)) => vec![header::Extension {
                kind: header::ext_type::BACKING_FORMAT,
                data: fmt.as_bytes().to_vec(),
            }],
            _ => Vec::new(),
        };
        let ext_bytes = header::encode_extensions(&extensions);
        let name_offset = header::V3_HEADER_LEN + ext_bytes.len();
        let (backing_file_offset, backing_file_size) = match &backing_info {
            Some((name, _, _)) => {
                if name_offset + name.len() > cs as usize {
                    return Err(crate::Error::InvalidArgument(
                        "qcow2: header, extensions and backing filename do not fit \
                         in one cluster — use a larger cluster size"
                            .into(),
                    ));
                }
                (name_offset as u64, name.len() as u32)
            }
            None => (0, 0),
        };

        // Build the header.
        let header = Header {
            version: header::VERSION_V3,
            backing_file_offset,
            backing_file_size,
            cluster_bits,
            size: virtual_size,
            crypt_method: 0,
            l1_size,
            l1_table_offset: l1_first_cluster * cs,
            refcount_table_offset: refcount_table_cluster * cs,
            refcount_table_clusters: 1,
            nb_snapshots: 0,
            snapshots_offset: 0,
            incompatible_features: 0,
            compatible_features: 0,
            autoclear_features: 0,
            refcount_order: 4,
            header_length: header::V3_HEADER_LEN as u32,
            compression_type: 0,
            extensions,
        };

        // Create the image file at exactly `file_len` bytes,
        // zero-filled by `set_len` (sparse).
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.set_len(file_len)?;

        // Write the header at byte 0, padded to the cluster.
        file.seek(SeekFrom::Start(0))?;
        let mut cluster0 = vec![0u8; cs as usize];
        cluster0[..header::V3_HEADER_LEN].copy_from_slice(&header.encode_v3());
        cluster0[header::V3_HEADER_LEN..name_offset].copy_from_slice(&ext_bytes);
        if let Some((name, _, _)) = &backing_info {
            cluster0[name_offset..name_offset + name.len()].copy_from_slice(name.as_bytes());
        }
        file.write_all(&cluster0)?;

        // L1 table starts all-zero — set_len already zero-filled it.
        let mut l1l2 = L1L2 {
            cluster_size: cs,
            cluster_bits,
            l2_entries: (cs / 8) as usize,
            l1: vec![0u64; l1_size as usize],
            l1_table_offset: l1_first_cluster * cs,
            l2_cache: std::collections::HashMap::new(),
            l2_cache_cap: 32,
            zero_flag: true,
        };

        // Refcount table + initial refcount block live in memory; flush
        // them so the on-disk view matches.
        let mut refcount = Refcount::new_fresh(
            cs,
            refcount_table_cluster * cs,
            refcount_block_cluster * cs,
            &initial,
        );
        refcount.flush(&mut file)?;
        l1l2.flush(&mut file)?;
        file.sync_data()?;

        let (backing_file, backing_format, backing) = match backing_info {
            Some((name, fmt, dev)) => (Some(name), fmt, Some(dev)),
            None => (None, None, None),
        };
        Ok(Self {
            file,
            header,
            cluster_size: cs,
            l1l2,
            refcount,
            file_len,
            cursor: 0,
            decomp_cache: None,
            read_only: false,
            backing,
            backing_file,
            backing_format,
        })
    }

    /// Read-only convenience: open and confirm this is a qcow2 image.
    pub fn probe<P: AsRef<Path>>(path: P) -> Result<bool> {
        let mut file = File::open(path.as_ref())?;
        let mut magic = [0u8; 4];
        if file.read_exact(&mut magic).is_err() {
            return Ok(false);
        }
        Ok(magic == header::MAGIC)
    }

    /// The decoded header — exposed for diagnostics.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Write `buf` to virtual offset `offset`, allocating physical
    /// clusters and L2 tables on demand.
    fn write_virtual(&mut self, mut offset: u64, mut buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        if self.read_only {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Qcow2Backend opened read-only — write refused",
            )));
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size: self.header.size,
            })?;
        if end > self.header.size {
            return Err(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size: self.header.size,
            });
        }
        let cs = self.cluster_size;
        while !buf.is_empty() {
            let in_cluster = offset & (cs - 1);
            let take = ((cs - in_cluster) as usize).min(buf.len());
            let (chunk, rest) = buf.split_at(take);
            let cluster_start = offset - in_cluster;
            let mapping = self.l1l2.map(&mut self.file, cluster_start)?;
            // Sparse fast path: writing zeros to a cluster that has no
            // physical mapping is a no-op — an unallocated qcow2 cluster
            // already reads back as zero, so allocating one just to fill
            // it with zeros bloats the file on disk for no semantic gain.
            // This is what made an 8 GiB ext2 repacked into qcow2 take
            // 8 GiB on disk: `Ext::format_with` calls `dev.zero_range`
            // across the whole image before formatting.
            //
            // With a backing file an unallocated cluster does NOT read as
            // zero — it reads through — so the shortcut would silently
            // fail to erase what the backing file holds. The ZERO-flagged
            // case is the same shortcut, already recorded on disk.
            let reads_as_zero = match mapping {
                Mapping::Unallocated => self.backing.is_none(),
                Mapping::Zero { .. } => true,
                _ => false,
            };
            if reads_as_zero && chunk.iter().all(|&b| b == 0) {
                offset += take as u64;
                buf = rest;
                continue;
            }
            let phys = match mapping {
                // Writing to a compressed cluster: copy it out to a fresh
                // plain cluster first (qemu's behaviour), then write into that.
                Mapping::Compressed {
                    host_offset,
                    byte_len,
                } => self.cow_compressed_cluster(cluster_start, host_offset, byte_len)?,
                // An unallocated cluster over a backing file has to be
                // copied up whole before the partial write lands: once the
                // L2 entry points somewhere, the backing file is shadowed
                // for the *entire* cluster, so the bytes this write does
                // not cover must already be there.
                Mapping::Unallocated if self.backing.is_some() => {
                    self.cow_from_backing(cluster_start)?
                }
                // A ZERO-flagged cluster becomes a real one; the flag has
                // to come off, and any bytes outside this write must read
                // as the zeros the flag promised.
                Mapping::Zero { .. } => self.materialise_zero_cluster(cluster_start)?,
                _ => self.ensure_mapping(cluster_start)?,
            };
            self.file.seek(SeekFrom::Start(phys + in_cluster))?;
            self.file.write_all(chunk)?;
            offset += take as u64;
            buf = rest;
        }
        Ok(())
    }

    /// Copy the cluster at virtual `cluster_start` up from the backing
    /// file into a freshly allocated cluster of our own, and return its
    /// physical offset.
    ///
    /// Bytes past the end of the backing file — a legal situation, since
    /// an overlay may be larger than its base — come back as zeros.
    fn cow_from_backing(&mut self, cluster_start: u64) -> Result<u64> {
        let cs = self.cluster_size;
        let mut cluster = vec![0u8; cs as usize];
        if let Some(backing) = self.backing.as_mut() {
            let backing_size = backing.total_size();
            if cluster_start < backing_size {
                let avail = (backing_size - cluster_start).min(cs) as usize;
                backing.read_at(cluster_start, &mut cluster[..avail])?;
            }
        }
        let phys = self.ensure_mapping(cluster_start)?;
        self.file.seek(SeekFrom::Start(phys))?;
        self.file.write_all(&cluster)?;
        Ok(phys)
    }

    /// Turn a ZERO-flagged cluster into an ordinary allocated one: make
    /// sure a cluster exists, fill it with the zeros the flag promised,
    /// and clear the flag. Returns the physical offset.
    fn materialise_zero_cluster(&mut self, cluster_start: u64) -> Result<u64> {
        let phys = self.ensure_mapping(cluster_start)?;
        self.file.seek(SeekFrom::Start(phys))?;
        self.file
            .write_all(&vec![0u8; self.cluster_size as usize])?;
        // `ensure_mapping` has loaded (or created) the L2, so the entry is
        // in cache and can be rewritten without the flag.
        let (l1_idx, l2_idx, _) = self.l1l2.split_addr(cluster_start);
        let l2_off = self.l1l2.l1[l1_idx] & l1l2::OFFSET_MASK;
        self.l1l2.set_l2_entry(l2_off, l2_idx, phys | COPIED)?;
        Ok(phys)
    }

    /// Mark the cluster at virtual `cluster_start` as reading all-zero.
    ///
    /// On v3 this sets the ZERO flag on the L2 entry, which needs an L2
    /// table but no data cluster — the cheap way to shadow a backing file
    /// with zeros. On v2, which has no such flag, there is no choice but
    /// to allocate a cluster and write real zeros into it.
    fn mark_zero_cluster(&mut self, cluster_start: u64) -> Result<()> {
        if self.header.version < 3 {
            let phys = match self.l1l2.map(&mut self.file, cluster_start)? {
                Mapping::Compressed {
                    host_offset,
                    byte_len,
                } => self.cow_compressed_cluster(cluster_start, host_offset, byte_len)?,
                _ => self.ensure_mapping(cluster_start)?,
            };
            self.file.seek(SeekFrom::Start(phys))?;
            self.file
                .write_all(&vec![0u8; self.cluster_size as usize])?;
            return Ok(());
        }
        // Release a compressed cluster's host range first; the ZERO flag
        // replaces its mapping entirely.
        if let Mapping::Compressed {
            host_offset,
            byte_len,
        } = self.l1l2.map(&mut self.file, cluster_start)?
        {
            self.refcount
                .release_range(&mut self.file, host_offset, byte_len)?;
            self.decomp_cache = None;
        }
        let l2_off = self.ensure_l2_table(cluster_start)?;
        let (_, l2_idx, _) = self.l1l2.split_addr(cluster_start);
        // Keep any cluster already allocated behind the flag — qemu does
        // the same, so a preallocated image stays preallocated.
        let existing = self.l1l2.l2_cache[&l2_off].entries[l2_idx] & l1l2::OFFSET_MASK;
        let value = if existing != 0 {
            existing | COPIED | ZERO
        } else {
            ZERO
        };
        self.l1l2.set_l2_entry(l2_off, l2_idx, value)?;
        Ok(())
    }

    /// Make sure the L2 table covering `vaddr` exists and is in cache,
    /// returning its physical offset. Allocates the L2 cluster if needed
    /// but never a data cluster.
    fn ensure_l2_table(&mut self, vaddr: u64) -> Result<u64> {
        let (l1_idx, _, _) = self.l1l2.split_addr(vaddr);
        if l1_idx >= self.l1l2.l1.len() {
            return Err(crate::Error::OutOfBounds {
                offset: vaddr,
                len: self.cluster_size,
                size: self.header.size,
            });
        }
        let l2_off = self.l1l2.l1[l1_idx] & l1l2::OFFSET_MASK;
        if l2_off != 0 {
            let _ = self.l1l2.lookup(&mut self.file, vaddr)?;
            return Ok(l2_off);
        }
        let cluster_idx = self
            .refcount
            .alloc_cluster(&mut self.file, &mut self.file_len)?;
        let new_end = (cluster_idx + 1) * self.cluster_size;
        if new_end > self.file_len {
            self.file_len = new_end;
        }
        self.file.set_len(self.file_len)?;
        let new_l2_off = cluster_idx * self.cluster_size;
        self.l1l2.insert_empty_l2(new_l2_off);
        self.l1l2.set_l1(l1_idx, new_l2_off | COPIED);
        Ok(new_l2_off)
    }

    /// Copy a compressed cluster out to a freshly allocated *plain* cluster:
    /// decompress it, write the bytes verbatim, repoint the L2 entry, and
    /// release the old compressed cluster's host-range refcounts. Returns the
    /// new plain cluster's physical byte offset, ready for the caller to write
    /// the actual (partial) update into.
    fn cow_compressed_cluster(
        &mut self,
        cluster_start: u64,
        host_offset: u64,
        byte_len: u64,
    ) -> Result<u64> {
        self.fill_decomp_cache(cluster_start, host_offset, byte_len)?;
        let content = self.decomp_cache.as_ref().unwrap().1.clone();

        let data_cluster = self
            .refcount
            .alloc_cluster(&mut self.file, &mut self.file_len)?;
        let new_off = data_cluster * self.cluster_size;
        let new_end = new_off + self.cluster_size;
        if new_end > self.file_len {
            self.file_len = new_end;
        }
        self.file.set_len(self.file_len)?;
        self.file.seek(SeekFrom::Start(new_off))?;
        self.file.write_all(&content)?;

        // Repoint the L2 entry at the new plain cluster.
        let (l1_idx, l2_idx, _) = self.l1l2.split_addr(cluster_start);
        let l2_off = self.l1l2.l1[l1_idx] & l1l2::OFFSET_MASK;
        self.l1l2.set_l2_entry(l2_off, l2_idx, new_off | COPIED)?;

        // Drop the old compressed cluster's references (it may have shared
        // host clusters with neighbours, which keep a positive refcount).
        self.refcount
            .release_range(&mut self.file, host_offset, byte_len)?;
        // The cluster is now plain; invalidate the decompressed-bytes cache so
        // the subsequent in-place write isn't shadowed by stale data.
        self.decomp_cache = None;
        Ok(new_off)
    }

    /// Make sure the cluster covering virtual offset `vaddr_cluster_aligned`
    /// has a physical mapping, allocating one if not. Returns the
    /// physical byte offset of the cluster.
    fn ensure_mapping(&mut self, vaddr: u64) -> Result<u64> {
        let (l1_idx, l2_idx, _) = self.l1l2.split_addr(vaddr);
        let l1_entry = self.l1l2.l1[l1_idx];
        let l2_off = l1_entry & l1l2::OFFSET_MASK;
        let (l2_off, _) = if l2_off == 0 {
            // Allocate an L2 cluster.
            let cluster_idx = self
                .refcount
                .alloc_cluster(&mut self.file, &mut self.file_len)?;
            // Make sure the file is long enough to hold the new L2 cluster.
            let new_end = (cluster_idx + 1) * self.cluster_size;
            if new_end > self.file_len {
                self.file_len = new_end;
            }
            self.file.set_len(self.file_len)?;
            let new_l2_off = cluster_idx * self.cluster_size;
            self.l1l2.insert_empty_l2(new_l2_off);
            self.l1l2.set_l1(l1_idx, new_l2_off | COPIED);
            (new_l2_off, l2_idx)
        } else {
            // Cache-load the L2 if it isn't already in cache.
            let _ = self.l1l2.lookup(&mut self.file, vaddr)?;
            (l2_off, l2_idx)
        };

        let l2_entry = self
            .l1l2
            .l2_cache
            .get(&l2_off)
            .expect("L2 just loaded/created")
            .entries[l2_idx];
        let data_off = l2_entry & l1l2::OFFSET_MASK;
        if data_off != 0 {
            return Ok(data_off);
        }
        // Allocate a data cluster.
        let data_cluster = self
            .refcount
            .alloc_cluster(&mut self.file, &mut self.file_len)?;
        let new_data_off = data_cluster * self.cluster_size;
        let new_end = new_data_off + self.cluster_size;
        if new_end > self.file_len {
            self.file_len = new_end;
        }
        self.file.set_len(self.file_len)?;
        self.l1l2
            .set_l2_entry(l2_off, l2_idx, new_data_off | COPIED)?;
        Ok(new_data_off)
    }

    /// Ensure `decomp_cache` holds the decompressed bytes of the compressed
    /// cluster at virtual `cluster_start`. Reads `byte_len` compressed bytes
    /// from `host_offset`, decodes them with the image's codec, and pads the
    /// result out to a full cluster.
    fn fill_decomp_cache(
        &mut self,
        cluster_start: u64,
        host_offset: u64,
        byte_len: u64,
    ) -> Result<()> {
        if self.decomp_cache.as_ref().map(|(k, _)| *k) == Some(cluster_start) {
            return Ok(());
        }
        let mut comp = vec![0u8; byte_len as usize];
        self.file.seek(SeekFrom::Start(host_offset))?;
        self.file.read_exact(&mut comp)?;
        let cs = self.cluster_size as usize;
        let mut plain = compress::decompress_cluster(self.header.compression_type, &comp, cs)?;
        plain.resize(cs, 0); // qcow2 compresses full clusters; pad short output
        self.decomp_cache = Some((cluster_start, plain));
        Ok(())
    }

    /// Read `buf.len()` bytes starting at virtual offset `offset`. Walks
    /// the L1/L2 mapping cluster-by-cluster; unallocated clusters read
    /// through to the backing file, or return zeros when there is none.
    fn read_virtual(&mut self, mut offset: u64, mut buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size: self.header.size,
            })?;
        if end > self.header.size {
            return Err(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size: self.header.size,
            });
        }
        let cs = self.cluster_size;
        while !buf.is_empty() {
            let in_cluster = offset & (cs - 1);
            let take = ((cs - in_cluster) as usize).min(buf.len());
            let (chunk, rest) = buf.split_at_mut(take);
            let cluster_start = offset - in_cluster;
            match self.l1l2.map(&mut self.file, cluster_start)? {
                Mapping::Normal(phys) => {
                    self.file.seek(SeekFrom::Start(phys + in_cluster))?;
                    self.file.read_exact(chunk)?;
                }
                // The ZERO flag says "genuinely zero here", which is
                // exactly what distinguishes it from Unallocated: it does
                // not fall through to the backing file.
                Mapping::Zero { .. } => {
                    chunk.fill(0);
                }
                Mapping::Unallocated => match self.backing.as_mut() {
                    Some(backing) => {
                        let at = cluster_start + in_cluster;
                        let backing_size = backing.total_size();
                        // The overlay may be larger than its base; past the
                        // base's end there is nothing to read, so zeros.
                        let avail = backing_size.saturating_sub(at).min(take as u64) as usize;
                        backing.read_at(at, &mut chunk[..avail])?;
                        chunk[avail..].fill(0);
                    }
                    None => chunk.fill(0),
                },
                Mapping::Compressed {
                    host_offset,
                    byte_len,
                } => {
                    self.fill_decomp_cache(cluster_start, host_offset, byte_len)?;
                    let cluster = &self.decomp_cache.as_ref().unwrap().1;
                    let from = in_cluster as usize;
                    chunk.copy_from_slice(&cluster[from..from + take]);
                }
            }
            offset += take as u64;
            buf = rest;
        }
        Ok(())
    }
}

impl Read for Qcow2Backend {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.header.size.saturating_sub(self.cursor);
        let n = (buf.len() as u64).min(remaining) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.read_virtual(self.cursor, &mut buf[..n])
            .map_err(io::Error::other)?;
        self.cursor += n as u64;
        Ok(n)
    }
}

impl Write for Qcow2Backend {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = self.header.size.saturating_sub(self.cursor);
        let n = (buf.len() as u64).min(remaining) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.write_virtual(self.cursor, &buf[..n])
            .map_err(io::Error::other)?;
        self.cursor += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        // The qcow2 layer flushes its metadata on `sync`; the std
        // `Write::flush` contract just says "drain buffered data", and
        // we have no internal buffer.
        Ok(())
    }
}

impl Seek for Qcow2Backend {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let size = self.header.size;
        let new = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::End(n) => size
                .checked_add_signed(n)
                .ok_or_else(|| io::Error::other("qcow2: seek past i64 bounds"))?,
            SeekFrom::Current(n) => self
                .cursor
                .checked_add_signed(n)
                .ok_or_else(|| io::Error::other("qcow2: seek past i64 bounds"))?,
        };
        self.cursor = new;
        Ok(self.cursor)
    }
}

impl BlockDevice for Qcow2Backend {
    fn block_size(&self) -> u32 {
        512
    }

    fn total_size(&self) -> u64 {
        self.header.size
    }

    fn sync(&mut self) -> Result<()> {
        if self.read_only {
            // No writes happened; nothing to flush. Calling
            // l1l2.flush / refcount.flush on a RO-opened file would
            // try to write back potentially clean caches and fail at
            // the syscall — skip them entirely.
            return Ok(());
        }
        self.l1l2.flush(&mut self.file)?;
        self.refcount.flush(&mut self.file)?;
        self.file.sync_data()?;
        Ok(())
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_virtual(offset, buf)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        self.write_virtual(offset, buf)
    }

    fn zero_range(&mut self, offset: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let size = self.header.size;
        let end = offset
            .checked_add(len)
            .ok_or(crate::Error::OutOfBounds { offset, len, size })?;
        if end > size {
            return Err(crate::Error::OutOfBounds { offset, len, size });
        }
        // Sparse-aware: an unallocated qcow2 cluster already reads as
        // zero, so a zero_range over unallocated clusters is a no-op.
        // Only clusters that already carry a physical mapping need to
        // be overwritten with zeros (we don't punch/discard yet — that
        // would require touching the refcount table). This is what
        // keeps an 8 GiB virtual image at a few megabytes on disk when
        // the FS formatter prefaces format with a full-device zero.
        //
        // Over a backing file that shortcut is wrong: an unallocated
        // cluster reads *through*, so it has to be marked zero instead.
        // A whole cluster gets the ZERO flag (no data cluster needed);
        // a partial one has to be copied up and zeroed in place, since
        // the flag covers the whole cluster or nothing.
        let cs = self.cluster_size;
        let zero = [0u8; 4096];
        let mut cur = offset;
        while cur < end {
            let in_cluster = cur & (cs - 1);
            let take = (cs - in_cluster).min(end - cur);
            let cluster_start = cur - in_cluster;
            let whole_cluster = in_cluster == 0 && take == cs;
            let mapping = self.l1l2.map(&mut self.file, cluster_start)?;
            if whole_cluster {
                // Flagging beats writing a cluster of zeros whether or not
                // there is a backing file, and it releases a compressed
                // cluster's host range on the way through.
                if !matches!(mapping, Mapping::Zero { .. }) {
                    self.mark_zero_cluster(cluster_start)?;
                }
                cur += take;
                continue;
            }
            let phys = match mapping {
                Mapping::Zero { .. } => None,
                Mapping::Unallocated if self.backing.is_some() => {
                    Some(self.cow_from_backing(cluster_start)?)
                }
                Mapping::Unallocated => None,
                Mapping::Normal(phys) => Some(phys),
                // A compressed cluster carries real data; copy it out to a
                // plain cluster so we can zero the requested sub-range in place.
                Mapping::Compressed {
                    host_offset,
                    byte_len,
                } => Some(self.cow_compressed_cluster(cluster_start, host_offset, byte_len)?),
            };
            if let Some(phys) = phys {
                self.file.seek(SeekFrom::Start(phys + in_cluster))?;
                let mut remaining = take;
                while remaining > 0 {
                    let n = remaining.min(zero.len() as u64) as usize;
                    self.file.write_all(&zero[..n])?;
                    remaining -= n as u64;
                }
            }
            cur += take;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test using a hand-rolled minimal qcow2 image: header, an
    /// empty L1 entry, and a small refcount table. The reader should
    /// return zeros for every offset (everything unallocated).
    #[test]
    fn read_returns_zeros_on_fresh_image() {
        // Generate a minimal v3 image in a tempfile and read it back.
        // Cluster size 64 KiB, virtual size 64 MiB, one L1 entry pointing
        // at nothing (everything unallocated).
        use std::io::Write;
        use tempfile::NamedTempFile;

        let tmp = NamedTempFile::new().unwrap();
        let cluster_size = 65536u64;
        let virtual_size = 64u64 * 1024 * 1024;
        let h = Header {
            version: header::VERSION_V3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: 16,
            size: virtual_size,
            crypt_method: 0,
            // virtual_size / cluster_size = 1024 clusters; one L2 cluster
            // (8192 entries) covers 8192 clusters, so l1_size = 1.
            l1_size: 1,
            l1_table_offset: 3 * cluster_size,
            refcount_table_offset: cluster_size,
            refcount_table_clusters: 1,
            nb_snapshots: 0,
            snapshots_offset: 0,
            incompatible_features: 0,
            compatible_features: 0,
            autoclear_features: 0,
            refcount_order: 4,
            header_length: header::V3_HEADER_LEN as u32,
            compression_type: 0,
            extensions: Vec::new(),
        };
        let mut f = std::fs::File::create(tmp.path()).unwrap();
        // Cluster 0: header padded to a cluster.
        let mut c0 = vec![0u8; cluster_size as usize];
        c0[..header::V3_HEADER_LEN].copy_from_slice(&h.encode_v3());
        f.write_all(&c0).unwrap();
        // Cluster 1: refcount table, all-zero (we don't read it on the
        // pure read path).
        f.write_all(&vec![0u8; cluster_size as usize]).unwrap();
        // Cluster 2: refcount block, all-zero.
        f.write_all(&vec![0u8; cluster_size as usize]).unwrap();
        // Cluster 3: L1 table, one entry == 0 (unallocated).
        f.write_all(&vec![0u8; cluster_size as usize]).unwrap();
        f.sync_all().unwrap();
        drop(f);

        let mut back = Qcow2Backend::open(tmp.path()).unwrap();
        assert_eq!(back.total_size(), virtual_size);
        assert_eq!(back.header.cluster_size(), cluster_size);

        // Reading from anywhere returns zeros.
        let mut buf = [0xffu8; 4096];
        back.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0));

        let mut buf2 = [0xffu8; 8192];
        back.read_at(virtual_size - 8192, &mut buf2).unwrap();
        assert!(buf2.iter().all(|&b| b == 0));

        // OOB rejection.
        let mut tail = [0u8; 16];
        let err = back.read_at(virtual_size, &mut tail).unwrap_err();
        assert!(matches!(err, crate::Error::OutOfBounds { .. }));

        // Read trait works via cursor.
        back.seek(SeekFrom::Start(0)).unwrap();
        let mut chunk = [0u8; 1024];
        let n = back.read(&mut chunk).unwrap();
        assert_eq!(n, 1024);
        assert!(chunk.iter().all(|&b| b == 0));
    }
}
