//! `.sparseimage` — Apple's single-file sparse disk image (`sprs`, v3).
//!
//! ## Layout
//!
//! All integers are big-endian. The file opens with a 4 KiB header:
//!
//! | offset | size | field |
//! |--------|------|-------|
//! | 0x00 | 4 | signature `sprs` |
//! | 0x04 | 4 | version, `3` |
//! | 0x08 | 4 | sectors (512 B) per band |
//! | 0x0C | 4 | flags; hdiutil sets `1` once a band is allocated |
//! | 0x10 | 4 | virtual size in sectors, or `0` when it does not fit 32 bits |
//! | 0x14 | 8 | file offset of the first extension header, `0` for none |
//! | 0x1C | 8 | virtual size in sectors |
//! | 0x40 | 4 × 1008 | band table |
//!
//! Band data follows the header in fixed-size *slots*, one band each, in
//! allocation order: table entry `i` holds the 1-based number of the
//! virtual band whose data sits in slot `i`, and a `0` entry ends the
//! table. Once the 1,008 entries are used up, the next band is preceded by
//! an extension header (again 4 KiB) right after the last slot:
//!
//! | offset | size | field |
//! |--------|------|-------|
//! | 0x00 | 4 | signature `sprs` |
//! | 0x04 | 4 | index of this extension header, from 0 |
//! | 0x08 | 4 | `1` |
//! | 0x0C | 8 | file offset of the next extension header, `0` for none |
//! | 0x38 | 4 × 1010 | band table, continuing the previous one |
//!
//! This is the layout `hdiutil` writes, confirmed against images of up to
//! three headers. Every band slot is a full band long; slots are never
//! freed in place (hdiutil reads a `0` entry as the end of the table), so
//! shrinking and compacting rewrite the image into a new file instead.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::{
    ShrinkPolicy, band_pieces, check_band_size, lock, range_is_zero, read_full_at, write_all_at,
    write_zeros_at,
};
use crate::Result;
use crate::block::BlockDevice;

const SIG: &[u8; 4] = b"sprs";
const VERSION: u32 = 3;
const NODE_SIZE: u64 = 4096;

const H_VERSION: usize = 0x04;
const H_SPB: usize = 0x08;
const H_FLAGS: usize = 0x0C;
const H_SECTORS32: usize = 0x10;
const H_NEXT: usize = 0x14;
const H_SECTORS64: usize = 0x1C;
const H_TABLE: usize = 0x40;

const X_INDEX: usize = 0x04;
const X_ONE: usize = 0x08;
const X_NEXT: usize = 0x0C;
const X_TABLE: usize = 0x38;

/// Entries in the first header's band table.
pub const FIRST_TABLE_ENTRIES: usize = (NODE_SIZE as usize - H_TABLE) / 4;
/// Entries in each extension header's band table.
pub const EXT_TABLE_ENTRIES: usize = (NODE_SIZE as usize - X_TABLE) / 4;

/// Largest virtual size accepted from a header, in sectors (2^55 bytes).
const MAX_SECTORS: u64 = 1 << 46;

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}
fn be64(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().unwrap())
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_be_bytes());
}

fn bad(msg: impl core::fmt::Display) -> crate::Error {
    crate::Error::InvalidImage(format!("sparseimage: {msg}"))
}

/// One band-table header (the first, or an extension).
#[derive(Debug, Clone)]
struct Node {
    /// File offset of the 4 KiB header.
    off: u64,
    /// The header as it should be on disk, except that the next-pointer
    /// field holds `persisted_next` until the pointed-to header is durable.
    raw: Vec<u8>,
    /// Used table entries (1-based band numbers), in slot order.
    entries: Vec<u32>,
    /// How many of `entries` are on disk.
    persisted_entries: usize,
    /// The next-header pointer we want on disk.
    next: u64,
    /// The next-header pointer that is on disk.
    persisted_next: u64,
    /// Header never written (a new extension).
    fresh: bool,
}

impl Node {
    fn first(&self) -> bool {
        self.off == 0
    }
    fn cap(&self) -> usize {
        if self.first() {
            FIRST_TABLE_ENTRIES
        } else {
            EXT_TABLE_ENTRIES
        }
    }
    fn table(&self) -> usize {
        if self.first() { H_TABLE } else { X_TABLE }
    }
    fn next_field(&self) -> usize {
        if self.first() { H_NEXT } else { X_NEXT }
    }
    fn slot_off(&self, i: usize, band_size: u64) -> u64 {
        self.off + NODE_SIZE + i as u64 * band_size
    }
    /// Offset just past this header's last possible slot.
    fn end(&self, band_size: u64) -> Option<u64> {
        (self.cap() as u64)
            .checked_mul(band_size)?
            .checked_add(self.off + NODE_SIZE)
    }
}

/// Parsed image metadata.
struct State {
    sectors_per_band: u32,
    band_size: u64,
    size: u64,
    nodes: Vec<Node>,
    map: HashMap<u32, u64>,
    file_len: u64,
}

fn load(file: &mut File) -> Result<State> {
    let file_len = file.metadata()?.len();
    if file_len < NODE_SIZE {
        return Err(bad("shorter than its 4 KiB header"));
    }
    let mut raw = vec![0u8; NODE_SIZE as usize];
    read_full_at(file, 0, &mut raw)?;
    if &raw[..4] != SIG {
        return Err(bad("no `sprs` signature"));
    }
    let version = be32(&raw, H_VERSION);
    if version != VERSION {
        return Err(crate::Error::Unsupported(format!(
            "sparseimage: version {version} (only 3 is supported)"
        )));
    }
    let spb = be32(&raw, H_SPB);
    let band_size = spb as u64 * 512;
    if spb == 0 || band_size > super::MAX_BAND_SIZE {
        return Err(bad(format_args!("band of {spb} sectors")));
    }
    let mut sectors = be64(&raw, H_SECTORS64);
    if sectors == 0 {
        sectors = be32(&raw, H_SECTORS32) as u64;
    }
    if sectors == 0 || sectors > MAX_SECTORS {
        return Err(bad(format_args!("virtual size of {sectors} sectors")));
    }
    let size = sectors * 512;
    let band_count = size.div_ceil(band_size);
    if band_count > u32::MAX as u64 {
        return Err(bad("more bands than its 32-bit table can number"));
    }

    let mut nodes: Vec<Node> = Vec::new();
    let mut map: HashMap<u32, u64> = HashMap::new();
    let mut off = 0u64;
    loop {
        if !nodes.is_empty() {
            raw = vec![0u8; NODE_SIZE as usize];
            read_full_at(file, off, &mut raw)?;
            if &raw[..4] != SIG {
                return Err(bad(format_args!(
                    "extension header at {off:#x} has no `sprs` signature"
                )));
            }
        }
        let mut node = Node {
            off,
            raw: Vec::new(),
            entries: Vec::new(),
            persisted_entries: 0,
            next: 0,
            persisted_next: 0,
            fresh: false,
        };
        let next = be64(&raw, node.next_field());
        let (tbl, cap) = (node.table(), node.cap());
        for i in 0..cap {
            let v = be32(&raw, tbl + 4 * i);
            // A zero entry ends the table — hdiutil reads nothing past it.
            if v == 0 {
                break;
            }
            if v as u64 > band_count {
                return Err(bad(format_args!(
                    "table names band {v}, past the last ({band_count})"
                )));
            }
            if map.insert(v - 1, node.slot_off(i, band_size)).is_some() {
                return Err(bad(format_args!("band {v} appears twice in the table")));
            }
            node.entries.push(v);
        }
        node.persisted_entries = node.entries.len();
        node.next = next;
        node.persisted_next = next;
        node.raw = raw.clone();
        let end = node
            .end(band_size)
            .ok_or_else(|| bad("header offset overflows"))?;
        let full = node.entries.len() == cap;
        nodes.push(node);
        if next == 0 {
            break;
        }
        if !full {
            return Err(bad("band table ends before the header it continues into"));
        }
        if next < end || !next.is_multiple_of(512) {
            return Err(bad(format_args!(
                "extension header at {next:#x} overlaps the band slots before it"
            )));
        }
        if next.checked_add(NODE_SIZE).is_none_or(|e| e > file_len) {
            return Err(bad(format_args!(
                "extension header at {next:#x} lies past the end of the file"
            )));
        }
        off = next;
    }
    Ok(State {
        sectors_per_band: spb,
        band_size,
        size,
        nodes,
        map,
        file_len,
    })
}

/// A fresh first header for `size` bytes in bands of `band_size`.
fn new_header(template: Option<&[u8]>, band_size: u64, size: u64, flags: u32) -> Vec<u8> {
    let mut raw = vec![0u8; NODE_SIZE as usize];
    if let Some(t) = template {
        // Keep whatever else the original header carried.
        raw[..H_TABLE].copy_from_slice(&t[..H_TABLE]);
    }
    raw[..4].copy_from_slice(SIG);
    put32(&mut raw, H_VERSION, VERSION);
    put32(&mut raw, H_SPB, (band_size / 512) as u32);
    put32(&mut raw, H_FLAGS, flags);
    set_size(&mut raw, size);
    put64(&mut raw, H_NEXT, 0);
    raw
}

fn set_size(raw: &mut [u8], size: u64) {
    let sectors = size / 512;
    put32(raw, H_SECTORS32, u32::try_from(sectors).unwrap_or(0));
    put64(raw, H_SECTORS64, sectors);
}

fn new_ext_header(index: u32) -> Vec<u8> {
    let mut raw = vec![0u8; NODE_SIZE as usize];
    raw[..4].copy_from_slice(SIG);
    put32(&mut raw, X_INDEX, index);
    put32(&mut raw, X_ONE, 1);
    raw
}

/// A [`BlockDevice`] over a `.sparseimage` file. See the
/// [module docs](super) for locking and crash-safety guarantees.
pub struct SparseImageBackend {
    file: File,
    path: PathBuf,
    read_only: bool,
    sectors_per_band: u32,
    band_size: u64,
    size: u64,
    nodes: Vec<Node>,
    /// 0-based virtual band → file offset of its slot.
    map: HashMap<u32, u64>,
    file_len: u64,
    /// The first header's size / flags fields changed and are unwritten.
    header_dirty: bool,
    cursor: u64,
}

impl std::fmt::Debug for SparseImageBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SparseImageBackend")
            .field("path", &self.path)
            .field("size", &self.size)
            .field("band_size", &self.band_size)
            .field("allocated_bands", &self.map.len())
            .field("headers", &self.nodes.len())
            .field("read_only", &self.read_only)
            .finish()
    }
}

impl SparseImageBackend {
    /// True when `path` is a file starting with the `sprs` signature.
    pub fn probe(path: &Path) -> Result<bool> {
        let Ok(meta) = std::fs::metadata(path) else {
            return Ok(false);
        };
        if !meta.is_file() || meta.len() < NODE_SIZE {
            return Ok(false);
        }
        let mut f = File::open(path)?;
        let mut sig = [0u8; 4];
        read_full_at(&mut f, 0, &mut sig)?;
        Ok(&sig == SIG)
    }

    /// Open an existing image for reading and writing, taking an
    /// exclusive lock on it.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_inner(path.as_ref(), false)
    }

    /// Open an existing image read-only, under a shared lock. Writes fail
    /// with `PermissionDenied`.
    pub fn open_read_only<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_inner(path.as_ref(), true)
    }

    fn open_inner(path: &Path, read_only: bool) -> Result<Self> {
        let mut file = OpenOptions::new().read(true).write(!read_only).open(path)?;
        lock(&file, !read_only, path)?;
        let st = load(&mut file)?;
        let mut me = Self::from_state(file, path, read_only, st);
        if !read_only {
            me.clear_stale_tail()?;
        }
        Ok(me)
    }

    fn from_state(file: File, path: &Path, read_only: bool, st: State) -> Self {
        let mut me = Self {
            file,
            path: path.to_path_buf(),
            read_only,
            sectors_per_band: 0,
            band_size: 0,
            size: 0,
            nodes: Vec::new(),
            map: HashMap::new(),
            file_len: 0,
            header_dirty: false,
            cursor: 0,
        };
        me.install(st);
        me
    }

    fn install(&mut self, st: State) {
        self.sectors_per_band = st.sectors_per_band;
        self.band_size = st.band_size;
        self.size = st.size;
        self.nodes = st.nodes;
        self.map = st.map;
        self.file_len = st.file_len;
        self.header_dirty = false;
        self.cursor = self.cursor.min(self.size);
    }

    /// Zero any entries left after the last table's terminator, so that a
    /// slot we allocate there cannot bring a stale entry after it back to
    /// life in hdiutil's eyes.
    fn clear_stale_tail(&mut self) -> Result<()> {
        let last = self.nodes.last_mut().expect("at least one header");
        let tbl = last.table();
        let from = tbl + 4 * last.entries.len();
        let to = tbl + 4 * last.cap();
        if last.raw[from..to].iter().all(|&b| b == 0) {
            return Ok(());
        }
        last.raw[from..to].fill(0);
        let off = last.off;
        let bytes = last.raw[from..to].to_vec();
        write_all_at(&mut self.file, off + from as u64, &bytes)?;
        self.file.sync_data()?;
        Ok(())
    }

    /// Create a new, empty image of `size` bytes (rounded up to a whole
    /// sector) in bands of `band_size` bytes (a multiple of 512; `hdiutil`
    /// uses [`DEFAULT_IMAGE_BAND_SIZE`](super::DEFAULT_IMAGE_BAND_SIZE)).
    /// An existing file at `path` is replaced — once its lock is ours.
    pub fn create<P: AsRef<Path>>(path: P, size: u64, band_size: u64) -> Result<Self> {
        let path = path.as_ref();
        check_band_size(band_size)?;
        let size = size
            .checked_next_multiple_of(512)
            .filter(|&s| s > 0 && s / 512 <= MAX_SECTORS)
            .ok_or_else(|| {
                crate::Error::InvalidArgument(format!("sparseimage: unusable size {size}"))
            })?;
        if size.div_ceil(band_size) > u32::MAX as u64 {
            return Err(crate::Error::InvalidArgument(
                "sparseimage: too many bands for the 32-bit band table — use a larger band size"
                    .into(),
            ));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        lock(&file, true, path)?;
        file.set_len(0)?;
        write_all_at(&mut file, 0, &new_header(None, band_size, size, 0))?;
        file.sync_all()?;
        let st = load(&mut file)?;
        Ok(Self::from_state(file, path, false, st))
    }

    /// Band size in bytes.
    pub fn band_size(&self) -> u64 {
        self.band_size
    }

    /// How many bands hold data in the file.
    pub fn allocated_bands(&self) -> u64 {
        self.map.len() as u64
    }

    /// Number of band-table headers (the first plus extensions).
    pub fn header_count(&self) -> usize {
        self.nodes.len()
    }

    fn check_writable(&self) -> Result<()> {
        if self.read_only {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "sparseimage: opened read-only",
            )));
        }
        Ok(())
    }

    fn check_range(&self, off: u64, len: usize) -> Result<()> {
        if off.checked_add(len as u64).is_none_or(|e| e > self.size) {
            return Err(crate::Error::OutOfBounds {
                offset: off,
                len: len as u64,
                size: self.size,
            });
        }
        Ok(())
    }

    fn read_virtual(&mut self, off: u64, buf: &mut [u8]) -> Result<()> {
        self.check_range(off, buf.len())?;
        for (band, inner, s, n) in band_pieces(off, buf.len(), self.band_size) {
            let piece = &mut buf[s..s + n];
            match self.map.get(&(band as u32)) {
                Some(&slot) => read_full_at(&mut self.file, slot + inner, piece)?,
                None => piece.fill(0),
            }
        }
        Ok(())
    }

    fn write_virtual(&mut self, off: u64, buf: &[u8]) -> Result<()> {
        self.check_writable()?;
        self.check_range(off, buf.len())?;
        for (band, inner, s, n) in band_pieces(off, buf.len(), self.band_size) {
            let piece = &buf[s..s + n];
            let band = band as u32;
            let slot = match self.map.get(&band) {
                Some(&slot) => slot,
                // Zeros into a hole are already there.
                None if piece.iter().all(|&b| b == 0) => continue,
                None => self.alloc_slot(band)?,
            };
            write_all_at(&mut self.file, slot + inner, piece)?;
            self.file_len = self.file_len.max(slot + inner + n as u64);
        }
        Ok(())
    }

    /// Give `band` the next free slot, zeroed, and record it in memory. The
    /// table entry reaches the disk at the next `sync`.
    fn alloc_slot(&mut self, band: u32) -> Result<u64> {
        let band_size = self.band_size;
        let last = self.nodes.last().expect("at least one header");
        if last.entries.len() == last.cap() {
            let off = last
                .end(band_size)
                .filter(|e| e.checked_add(NODE_SIZE + band_size).is_some())
                .ok_or_else(|| bad("file offset overflows"))?;
            let index = (self.nodes.len() - 1) as u32;
            self.nodes.last_mut().unwrap().next = off;
            self.nodes.push(Node {
                off,
                raw: new_ext_header(index),
                entries: Vec::new(),
                persisted_entries: 0,
                next: 0,
                persisted_next: 0,
                fresh: true,
            });
        }
        let node = self.nodes.last_mut().unwrap();
        let i = node.entries.len();
        let slot = node.slot_off(i, band_size);
        let at = node.table() + 4 * i;
        put32(&mut node.raw, at, band + 1);
        node.entries.push(band + 1);

        // Anything already in the file under the slot (or under a new
        // header) is leftover; the slot must read as zeros.
        let node_off = node.off;
        let span_start = if node.fresh && i == 0 { node_off } else { slot };
        let span_end = slot + band_size;
        if span_start < self.file_len {
            let n = span_end.min(self.file_len) - span_start;
            write_zeros_at(&mut self.file, span_start, n)?;
        }
        if span_end > self.file_len {
            self.file.set_len(span_end)?;
            self.file_len = span_end;
        }
        self.map.insert(band, slot);
        if be32(&self.nodes[0].raw, H_FLAGS) == 0 {
            put32(&mut self.nodes[0].raw, H_FLAGS, 1);
            self.header_dirty = true;
        }
        Ok(slot)
    }

    fn metadata_dirty(&self) -> bool {
        self.header_dirty
            || self.nodes.iter().any(|n| {
                n.fresh || n.entries.len() != n.persisted_entries || n.next != n.persisted_next
            })
    }

    /// Write the band tables: data first, then table entries and new
    /// headers, then the pointers that link new headers in.
    fn flush_metadata(&mut self) -> Result<()> {
        if !self.metadata_dirty() {
            return Ok(());
        }
        // 1. Make the band data the new entries will point at durable.
        self.file.sync_data()?;
        // 2. Headers and entries, each next-pointer still at its old value.
        for k in 0..self.nodes.len() {
            let node = &self.nodes[k];
            let nf = node.next_field();
            let mut raw = node.raw.clone();
            put64(&mut raw, nf, node.persisted_next);
            if node.fresh {
                write_all_at(&mut self.file, node.off, &raw)?;
            } else {
                if k == 0 && self.header_dirty {
                    // Size and flags share sector 0 with the next pointer
                    // and the first entries: one sector, one write.
                    write_all_at(&mut self.file, 0, &raw[..512])?;
                }
                if node.entries.len() != node.persisted_entries {
                    let from = node.table() + 4 * node.persisted_entries;
                    let to = node.table() + 4 * node.entries.len();
                    write_all_at(&mut self.file, node.off + from as u64, &raw[from..to])?;
                }
            }
        }
        self.file.sync_data()?;
        // 3. Link new headers in.
        let mut linked = false;
        for node in &mut self.nodes {
            if node.next != node.persisted_next {
                let nf = node.next_field();
                put64(&mut node.raw, nf, node.next);
                let off = node.off + nf as u64;
                let bytes = node.next.to_be_bytes();
                write_all_at(&mut self.file, off, &bytes)?;
                linked = true;
            }
        }
        if linked {
            self.file.sync_data()?;
        }
        for node in &mut self.nodes {
            node.fresh = false;
            node.persisted_entries = node.entries.len();
            node.persisted_next = node.next;
            let nf = node.next_field();
            put64(&mut node.raw, nf, node.next);
        }
        self.header_dirty = false;
        Ok(())
    }

    /// Change the virtual size to `new_size` bytes (a multiple of 512).
    ///
    /// Growing only rewrites the header sector. Shrinking checks the bytes
    /// past the new end first: under [`ShrinkPolicy::RequireZero`] any
    /// nonzero byte fails the call with the image unchanged. Bands that
    /// fall wholly past the new end are dropped by rewriting the image into
    /// a new file that is renamed over this one; a band straddling the end
    /// has its tail zeroed in place, so growing again later reads zeros.
    pub fn resize(&mut self, new_size: u64, policy: ShrinkPolicy) -> Result<()> {
        self.check_writable()?;
        if new_size == 0 || !new_size.is_multiple_of(512) || new_size / 512 > MAX_SECTORS {
            return Err(crate::Error::InvalidArgument(format!(
                "sparseimage: new size {new_size} must be a nonzero multiple of 512"
            )));
        }
        let band_size = self.band_size;
        let new_bands = new_size.div_ceil(band_size);
        if new_bands > u32::MAX as u64 {
            return Err(crate::Error::InvalidArgument(
                "sparseimage: too many bands for the 32-bit band table".into(),
            ));
        }
        self.flush_metadata()?;
        if new_size >= self.size {
            set_size(&mut self.nodes[0].raw, new_size);
            self.header_dirty = true;
            self.size = new_size;
            self.flush_metadata()?;
            return Ok(());
        }

        // Shrink: what lies past the new end?
        let mut affected: Vec<(u32, u64)> = self
            .map
            .iter()
            .filter(|&(&b, _)| (b as u64 + 1) * band_size > new_size)
            .map(|(&b, &s)| (b, s))
            .collect();
        affected.sort_unstable();
        if policy == ShrinkPolicy::RequireZero {
            for &(b, slot) in &affected {
                let start = (b as u64 * band_size).max(new_size);
                let end = ((b as u64 + 1) * band_size).min(self.size);
                let from = slot + (start - b as u64 * band_size);
                if !range_is_zero(&mut self.file, from, end - start)? {
                    return Err(crate::Error::InvalidArgument(format!(
                        "sparseimage: shrinking to {new_size} bytes would discard nonzero data \
                         at offset {start} — pass ShrinkPolicy::Discard to drop it"
                    )));
                }
            }
        }
        if affected.iter().any(|&(b, _)| b as u64 >= new_bands) {
            let keep: Vec<u32> = self
                .slot_order()
                .into_iter()
                .filter(|&b| (b as u64) < new_bands)
                .collect();
            return self.rewrite(new_size, &keep);
        }
        // Only the straddling band is affected: zero its tail, then shrink.
        for &(b, slot) in &affected {
            let inner = new_size - b as u64 * band_size;
            write_zeros_at(&mut self.file, slot + inner, band_size - inner)?;
        }
        self.file.sync_data()?;
        set_size(&mut self.nodes[0].raw, new_size);
        self.header_dirty = true;
        self.size = new_size;
        self.cursor = self.cursor.min(new_size);
        self.flush_metadata()
    }

    /// Drop every band whose contents are entirely zero, returning how
    /// many went. The image is rewritten into a new file that replaces
    /// this one by rename, so a failure part-way leaves it as it was.
    ///
    /// This is not filesystem-aware: space a filesystem has freed but not
    /// zeroed stays allocated.
    pub fn compact(&mut self) -> Result<u64> {
        self.check_writable()?;
        self.flush_metadata()?;
        let mut keep = Vec::new();
        let mut dropped = 0u64;
        for b in self.slot_order() {
            let slot = self.map[&b];
            if range_is_zero(&mut self.file, slot, self.band_size)? {
                dropped += 1;
            } else {
                keep.push(b);
            }
        }
        if dropped > 0 {
            self.rewrite(self.size, &keep)?;
        }
        Ok(dropped)
    }

    /// Allocated bands (0-based), in slot order.
    fn slot_order(&self) -> Vec<u32> {
        self.nodes
            .iter()
            .flat_map(|n| n.entries.iter().map(|&v| v - 1))
            .collect()
    }

    /// Write a fresh image of `new_size` bytes holding `keep` (0-based
    /// bands, copied in that order) next to this one, then rename it into
    /// place. Bytes past `new_size` are zeroed in the copy.
    fn rewrite(&mut self, new_size: u64, keep: &[u32]) -> Result<()> {
        let band_size = self.band_size;
        let name = self.path.file_name().ok_or_else(|| {
            crate::Error::InvalidArgument("sparseimage: path has no file name".into())
        })?;
        let mut tmp_name = name.to_os_string();
        tmp_name.push(".fstool-tmp");
        let tmp_path = self.path.with_file_name(tmp_name);

        let result = (|| -> Result<File> {
            let mut opts = OpenOptions::new();
            opts.read(true).write(true).create(true).truncate(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                // READ | WRITE | DELETE, so the open handle can be renamed.
                opts.share_mode(7);
            }
            let mut out = opts.open(&tmp_path)?;
            lock(&out, true, &tmp_path)?;
            let flags = if keep.is_empty() { 0 } else { 1 };
            let mut header = new_header(Some(&self.nodes[0].raw), band_size, new_size, flags);
            let mut node_off = 0u64;
            let mut node_raw_first = true;
            let mut idx = 0usize;
            let mut ext_index = 0u32;
            let mut buf = vec![0u8; band_size.min(1 << 20) as usize];
            for &b in keep {
                let cap = if node_raw_first {
                    FIRST_TABLE_ENTRIES
                } else {
                    EXT_TABLE_ENTRIES
                };
                if idx == cap {
                    let next = node_off + NODE_SIZE + cap as u64 * band_size;
                    put64(
                        &mut header,
                        if node_raw_first { H_NEXT } else { X_NEXT },
                        next,
                    );
                    write_all_at(&mut out, node_off, &header)?;
                    header = new_ext_header(ext_index);
                    ext_index += 1;
                    node_off = next;
                    node_raw_first = false;
                    idx = 0;
                }
                let tbl = if node_raw_first { H_TABLE } else { X_TABLE };
                put32(&mut header, tbl + 4 * idx, b + 1);
                let dst = node_off + NODE_SIZE + idx as u64 * band_size;
                let src = self.map[&b];
                let band_start = b as u64 * band_size;
                let mut done = 0u64;
                while done < band_size {
                    let n = (band_size - done).min(buf.len() as u64) as usize;
                    let chunk = &mut buf[..n];
                    read_full_at(&mut self.file, src + done, chunk)?;
                    // Zero whatever lies past the new end.
                    let vpos = band_start + done;
                    if vpos + n as u64 > new_size {
                        let keep_n = new_size.saturating_sub(vpos) as usize;
                        chunk[keep_n..].fill(0);
                    }
                    write_all_at(&mut out, dst + done, chunk)?;
                    done += n as u64;
                }
                idx += 1;
            }
            write_all_at(&mut out, node_off, &header)?;
            let end = if keep.is_empty() {
                NODE_SIZE
            } else {
                node_off + NODE_SIZE + idx as u64 * band_size
            };
            out.set_len(end)?;
            out.sync_all()?;
            Ok(out)
        })();
        let out = match result {
            Ok(f) => f,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e);
            }
        };

        // Swap the new file in.
        #[cfg(not(windows))]
        {
            if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e.into());
            }
            self.file = out;
        }
        #[cfg(windows)]
        {
            // The original can't be replaced while we hold it open.
            let old = std::mem::replace(&mut self.file, out);
            drop(old);
            if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
                // Put the original back.
                let reopened = OpenOptions::new().read(true).write(true).open(&self.path)?;
                lock(&reopened, true, &self.path)?;
                self.file = reopened;
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e.into());
            }
        }
        if let Some(dir) = self.path.parent() {
            let dir = if dir.as_os_str().is_empty() {
                Path::new(".")
            } else {
                dir
            };
            let _ = super::sync_dir(dir);
        }
        let st = load(&mut self.file)?;
        self.install(st);
        Ok(())
    }
}

impl Read for SparseImageBackend {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (buf.len() as u64).min(self.size.saturating_sub(self.cursor)) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.read_virtual(self.cursor, &mut buf[..n])
            .map_err(io::Error::other)?;
        self.cursor += n as u64;
        Ok(n)
    }
}

impl Write for SparseImageBackend {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = (buf.len() as u64).min(self.size.saturating_sub(self.cursor)) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.write_virtual(self.cursor, &buf[..n])
            .map_err(io::Error::other)?;
        self.cursor += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sync().map_err(io::Error::other)
    }
}

impl Seek for SparseImageBackend {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(n) => self.size.checked_add_signed(n),
            SeekFrom::Current(n) => self.cursor.checked_add_signed(n),
        };
        self.cursor = new.ok_or_else(|| io::Error::other("sparseimage: seek out of range"))?;
        Ok(self.cursor)
    }
}

impl BlockDevice for SparseImageBackend {
    fn block_size(&self) -> u32 {
        512
    }

    fn total_size(&self) -> u64 {
        self.size
    }

    fn sync(&mut self) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        self.flush_metadata()?;
        self.file.sync_data()?;
        Ok(())
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_virtual(offset, buf)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        self.write_virtual(offset, buf)
    }
}

impl Drop for SparseImageBackend {
    /// Best-effort table write-back for a backend dropped without
    /// [`sync`](BlockDevice::sync), in the same data-then-table order.
    fn drop(&mut self) {
        if !self.read_only {
            let _ = self.flush_metadata();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// The image file's bytes, read through the backend's own handle:
    /// Windows locks are mandatory, so a second handle can't read the
    /// file while the backend holds it.
    fn raw_bytes(img: &mut SparseImageBackend) -> Vec<u8> {
        let len = img.file.metadata().unwrap().len();
        let mut v = vec![0u8; len as usize];
        read_full_at(&mut img.file, 0, &mut v).unwrap();
        v
    }

    #[test]
    fn table_capacities_match_hdiutil() {
        assert_eq!(FIRST_TABLE_ENTRIES, 1008);
        assert_eq!(EXT_TABLE_ENTRIES, 1010);
    }

    #[test]
    fn holes_read_zero_and_writes_allocate() {
        let d = tmpdir();
        let p = d.path().join("a.sparseimage");
        let mut img = SparseImageBackend::create(&p, 10 * 4096, 4096).unwrap();
        assert_eq!(img.total_size(), 40960);
        let mut buf = vec![0xAAu8; 40960];
        img.read_at(0, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0));
        // Zeros into a hole allocate nothing.
        img.write_at(0, &[0u8; 8192]).unwrap();
        assert_eq!(img.allocated_bands(), 0);
        // A write straddling bands 2 and 3.
        img.write_at(3 * 4096 - 10, &[7u8; 20]).unwrap();
        assert_eq!(img.allocated_bands(), 2);
        img.write_at(9 * 4096 + 5, b"tail").unwrap();
        img.sync().unwrap();
        drop(img);
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 4096 + 3 * 4096);

        let mut img = SparseImageBackend::open_read_only(&p).unwrap();
        assert_eq!(img.allocated_bands(), 3);
        let mut buf = vec![0u8; 40960];
        img.read_at(0, &mut buf).unwrap();
        let mut want = vec![0u8; 40960];
        want[3 * 4096 - 10..3 * 4096 + 10].fill(7);
        want[9 * 4096 + 5..9 * 4096 + 9].copy_from_slice(b"tail");
        assert_eq!(buf, want);
        // Allocation order: band 2 (1-based 3), band 3, band 9.
        let raw = std::fs::read(&p).unwrap();
        assert_eq!(
            &raw[0x40..0x50],
            &[0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 10, 0, 0, 0, 0]
        );
        assert_eq!(be32(&raw, H_FLAGS), 1);
        assert!(img.write_at(0, b"x").is_err());
        assert!(img.read_at(40960 - 1, &mut [0u8; 2]).is_err());
    }

    #[test]
    fn extension_headers_chain() {
        let d = tmpdir();
        let p = d.path().join("big.sparseimage");
        let bands = (FIRST_TABLE_ENTRIES + EXT_TABLE_ENTRIES + 5) as u64;
        let mut img = SparseImageBackend::create(&p, (bands + 3) * 512, 512).unwrap();
        // Allocate in reverse to make slot order differ from band order.
        for b in (0..bands).rev() {
            let v = (b as u32 + 1).to_le_bytes();
            img.write_at(b * 512 + 7, &v).unwrap();
        }
        img.sync().unwrap();
        assert_eq!(img.header_count(), 3);
        drop(img);
        let raw = std::fs::read(&p).unwrap();
        let next1 = be64(&raw, H_NEXT);
        assert_eq!(next1, NODE_SIZE + FIRST_TABLE_ENTRIES as u64 * 512);
        assert_eq!(be32(&raw, next1 as usize + X_INDEX), 0);
        let next2 = be64(&raw, next1 as usize + X_NEXT);
        assert_eq!(next2, next1 + NODE_SIZE + EXT_TABLE_ENTRIES as u64 * 512);
        assert_eq!(be32(&raw, next2 as usize + X_INDEX), 1);

        let mut img = SparseImageBackend::open(&p).unwrap();
        assert_eq!(img.allocated_bands(), bands);
        for b in 0..bands + 3 {
            let mut v = [0u8; 4];
            img.read_at(b * 512 + 7, &mut v).unwrap();
            let want = if b < bands { b as u32 + 1 } else { 0 };
            assert_eq!(u32::from_le_bytes(v), want, "band {b}");
        }
        // Compact: zero half the bands, then drop them.
        for b in (0..bands).step_by(2) {
            img.write_at(b * 512, &[0u8; 512]).unwrap();
        }
        let dropped = img.compact().unwrap();
        assert_eq!(dropped, bands.div_ceil(2));
        assert_eq!(img.allocated_bands(), bands / 2);
        assert_eq!(img.header_count(), 2);
        for b in 0..bands {
            let mut v = [0u8; 4];
            img.read_at(b * 512 + 7, &mut v).unwrap();
            let want = if b % 2 == 1 { b as u32 + 1 } else { 0 };
            assert_eq!(u32::from_le_bytes(v), want, "band {b} after compact");
        }
        drop(img);
        assert!(!d.path().join("big.sparseimage.fstool-tmp").exists());
        let img = SparseImageBackend::open(&p).unwrap();
        assert_eq!(img.allocated_bands(), bands / 2);
    }

    #[test]
    fn unsynced_allocation_is_unreachable_not_garbage() {
        let d = tmpdir();
        let p = d.path().join("c.sparseimage");
        let mut img = SparseImageBackend::create(&p, 8 * 4096, 4096).unwrap();
        img.write_at(0, b"synced").unwrap();
        img.sync().unwrap();
        img.write_at(4096, b"lost").unwrap();
        // Simulate a crash: the file as it stands before any write-back.
        let snapshot = raw_bytes(&mut img);
        drop(img);
        let p = d.path().join("crashed.sparseimage");
        std::fs::write(&p, snapshot).unwrap();
        let mut img = SparseImageBackend::open_read_only(&p).unwrap();
        assert_eq!(img.allocated_bands(), 1);
        let mut b = [0u8; 6];
        img.read_at(0, &mut b).unwrap();
        assert_eq!(&b, b"synced");
        let mut b = [0u8; 4];
        img.read_at(4096, &mut b).unwrap();
        assert_eq!(b, [0; 4]);
    }

    #[test]
    fn resize_grow_and_shrink() {
        let d = tmpdir();
        let p = d.path().join("r.sparseimage");
        let mut img = SparseImageBackend::create(&p, 8 * 4096, 4096).unwrap();
        img.write_at(4096 + 100, b"keep").unwrap();
        img.write_at(6 * 4096, b"far").unwrap();
        img.resize(16 * 4096, ShrinkPolicy::RequireZero).unwrap();
        assert_eq!(img.total_size(), 16 * 4096);
        let before = raw_bytes(&mut img);
        // Shrinking over nonzero data is refused and changes nothing.
        let err = img.resize(4 * 4096, ShrinkPolicy::RequireZero);
        assert!(err.is_err());
        assert_eq!(raw_bytes(&mut img), before);
        assert_eq!(img.total_size(), 16 * 4096);
        // Straddling shrink with only zeros past the end: in place.
        img.write_at(6 * 4096, &[0u8; 3]).unwrap();
        img.resize(6 * 4096 + 512, ShrinkPolicy::RequireZero)
            .unwrap();
        assert_eq!(img.allocated_bands(), 2);
        // Discard drops band 6 and zeros band 1's tail.
        img.write_at(6 * 4096, b"zz").unwrap();
        img.resize(4096 + 512, ShrinkPolicy::Discard).unwrap();
        assert_eq!(img.allocated_bands(), 1);
        assert_eq!(img.total_size(), 4096 + 512);
        img.resize(8 * 4096, ShrinkPolicy::RequireZero).unwrap();
        let mut b = vec![0u8; 8 * 4096];
        img.read_at(0, &mut b).unwrap();
        let mut want = vec![0u8; 8 * 4096];
        want[4096 + 100..4096 + 104].copy_from_slice(b"keep");
        assert_eq!(b, want);
        drop(img);
        let img = SparseImageBackend::open(&p).unwrap();
        assert_eq!(img.total_size(), 8 * 4096);
        drop(img);
    }

    #[test]
    fn writer_lock_is_exclusive() {
        let d = tmpdir();
        let p = d.path().join("l.sparseimage");
        let img = SparseImageBackend::create(&p, 4096, 4096).unwrap();
        assert!(SparseImageBackend::open(&p).is_err());
        assert!(SparseImageBackend::open_read_only(&p).is_err());
        drop(img);
        let r1 = SparseImageBackend::open_read_only(&p).unwrap();
        let _r2 = SparseImageBackend::open_read_only(&p).unwrap();
        assert!(SparseImageBackend::open(&p).is_err());
        drop(r1);
    }

    fn write_raw(d: &tempfile::TempDir, raw: &[u8]) -> PathBuf {
        let p = d.path().join("m.sparseimage");
        std::fs::write(&p, raw).unwrap();
        p
    }

    #[test]
    fn malformed_headers_rejected() {
        let d = tmpdir();
        let good = new_header(None, 4096, 16 * 4096, 1);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("short", good[..100].to_vec()),
            ("version", {
                let mut r = good.clone();
                put32(&mut r, H_VERSION, 2);
                r
            }),
            ("zero band", {
                let mut r = good.clone();
                put32(&mut r, H_SPB, 0);
                r
            }),
            ("zero size", {
                let mut r = good.clone();
                set_size(&mut r, 0);
                r
            }),
            ("huge size", {
                let mut r = good.clone();
                put64(&mut r, H_SECTORS64, u64::MAX);
                r
            }),
            ("out of range", {
                let mut r = good.clone();
                put32(&mut r, H_TABLE, 17);
                r
            }),
            ("duplicate", {
                let mut r = good.clone();
                put32(&mut r, H_TABLE, 2);
                put32(&mut r, H_TABLE + 4, 2);
                r
            }),
            ("next past eof", {
                let mut r = new_header(None, 512, 2000 * 512, 1);
                for i in 0..FIRST_TABLE_ENTRIES {
                    put32(&mut r, H_TABLE + 4 * i, i as u32 + 1);
                }
                put64(&mut r, H_NEXT, NODE_SIZE + FIRST_TABLE_ENTRIES as u64 * 512);
                r
            }),
            ("next while table ends", {
                let mut r = good.clone();
                put64(&mut r, H_NEXT, 1 << 40);
                r
            }),
            ("too many bands", {
                let mut r = good.clone();
                put32(&mut r, H_SPB, 1);
                put64(&mut r, H_SECTORS64, (u32::MAX as u64) + 2);
                r
            }),
        ];
        for (what, raw) in cases {
            let p = write_raw(&d, &raw);
            assert!(SparseImageBackend::open_read_only(&p).is_err(), "{what}");
        }
        // Overlapping extension header: tiny bands, full first table,
        // next pointing inside its own slots.
        let mut r = new_header(None, 512, 2000 * 512, 1);
        for i in 0..FIRST_TABLE_ENTRIES {
            put32(&mut r, H_TABLE + 4 * i, i as u32 + 1);
        }
        put64(&mut r, H_NEXT, 8192);
        r.resize(NODE_SIZE as usize + FIRST_TABLE_ENTRIES * 512 + 4096, 0);
        r[8192..8196].copy_from_slice(SIG);
        let p = write_raw(&d, &r);
        assert!(SparseImageBackend::open_read_only(&p).is_err());
        // Same with a correct pointer opens.
        put64(&mut r, H_NEXT, NODE_SIZE + FIRST_TABLE_ENTRIES as u64 * 512);
        let at = NODE_SIZE as usize + FIRST_TABLE_ENTRIES * 512;
        r[at..at + 4].copy_from_slice(SIG);
        let p = write_raw(&d, &r);
        let img = SparseImageBackend::open_read_only(&p).unwrap();
        assert_eq!(img.header_count(), 2);
        drop(img);
        // Garbage of every length never panics.
        for len in [0usize, 3, 4, 4095, 4096, 5000] {
            let mut raw = vec![0x5Au8; len];
            if len >= 8 {
                raw[..4].copy_from_slice(SIG);
                put32(&mut raw, 4, 3);
            }
            let p = write_raw(&d, &raw);
            let _ = SparseImageBackend::open_read_only(&p);
        }
    }

    #[test]
    fn stale_entries_past_terminator_are_cleared() {
        let d = tmpdir();
        let mut r = new_header(None, 4096, 8 * 4096, 1);
        put32(&mut r, H_TABLE, 1);
        put32(&mut r, H_TABLE + 8, 5); // after the terminator
        r.resize(NODE_SIZE as usize + 3 * 4096, 0xEE);
        let p = write_raw(&d, &r);
        let mut img = SparseImageBackend::open(&p).unwrap();
        assert_eq!(img.allocated_bands(), 1);
        let mut b = [0u8; 4];
        img.read_at(4 * 4096, &mut b).unwrap();
        assert_eq!(b, [0; 4]);
        img.write_at(2 * 4096, b"new").unwrap();
        img.sync().unwrap();
        drop(img);
        let raw = std::fs::read(&p).unwrap();
        assert_eq!(be32(&raw, H_TABLE + 4), 3);
        assert_eq!(be32(&raw, H_TABLE + 8), 0);
        // The reused slot was zeroed apart from the write.
        let slot = NODE_SIZE as usize + 4096;
        assert_eq!(&raw[slot..slot + 3], b"new");
        assert!(raw[slot + 3..slot + 4096].iter().all(|&b| b == 0));
    }
}
