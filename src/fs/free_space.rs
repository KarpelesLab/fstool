//! Free-space maps: which byte ranges of a volume its filesystem is not
//! using.
//!
//! [`free_space`] reads a filesystem's own allocation records — the HFS+
//! allocation file, the classic HFS volume bitmap, the FAT, the exFAT
//! allocation bitmap, ext2/3/4 block bitmaps — and reports the byte ranges
//! they mark free. Space managers use it to give unused space back: a
//! sparse image can release bands that only hold free space
//! (`block::sparse::reclaim`, with the `sparse-image` feature), which
//! plain zero-band compaction cannot, since a deleted file's bytes are
//! still there.
//!
//! The map is only as trustworthy as the filesystem, so it is produced
//! only for a volume that says it is consistent and was cleanly unmounted:
//! a volume marked dirty, mounted, inconsistent, or with an unreplayed
//! journal is refused with [`Error::InvalidImage`](crate::Error::InvalidImage).
//! Layouts this module cannot read with certainty (HFS+ embedded in an HFS
//! wrapper, an allocation file spilling into overflow extents, ext4
//! `meta_bg` or `bigalloc`, TexFAT) are refused with
//! [`Error::Unsupported`](crate::Error::Unsupported) rather than guessed,
//! and so is any filesystem not listed here (NTFS, APFS, XFS, …). Uncertain
//! regions are reported as *used*: an ext4 group whose bitmap was never
//! initialised contributes nothing.
//!
//! Detection is by the filesystem's own signatures, and a device on which
//! more than one supported signature matches is refused as ambiguous.

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Range;

use crate::Result;
use crate::block::BlockDevice;

/// Unused byte ranges of one volume. See the [module docs](self).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FreeSpace {
    /// Which filesystem reported it: `"hfs+"`, `"hfs"`, `"fat12"`,
    /// `"fat16"`, `"fat32"`, `"exfat"` or `"ext"`.
    pub fs: &'static str,
    /// The filesystem's allocation unit (block or cluster), in bytes.
    pub allocation_unit: u64,
    /// Bytes from the start of the device the filesystem spans.
    pub volume_size: u64,
    /// Free byte ranges, relative to the start of the device: sorted,
    /// non-overlapping, non-adjacent, all inside `[0, volume_size)`.
    pub ranges: Vec<Range<u64>>,
}

impl FreeSpace {
    /// Total free bytes.
    pub fn free_bytes(&self) -> u64 {
        self.ranges.iter().map(|r| r.end - r.start).sum()
    }
}

/// Report the free byte ranges of the filesystem on `dev`, which must
/// start at the filesystem's first byte (slice a partition first). See
/// the [module docs](self) for what is supported and what is refused.
pub fn free_space(dev: &mut dyn BlockDevice) -> Result<FreeSpace> {
    let size = dev.total_size();
    let mut head = vec![0u8; 2048.min(size as usize)];
    dev.read_at(0, &mut head)?;
    head.resize(2048, 0);

    let mut found: Vec<&'static str> = Vec::new();
    if &head[3..11] == b"EXFAT   " {
        found.push("exfat");
    }
    if &head[3..11] == b"NTFS    " {
        return Err(unsupported("NTFS"));
    }
    if fat_candidate(dev, &head)? {
        found.push("fat");
    }
    match &head[1024..1026] {
        b"H+" | b"HX" => found.push("hfs+"),
        b"BD" => found.push("hfs"),
        _ => {}
    }
    if le16(&head, 1024 + 56) == 0xEF53 {
        found.push("ext");
    }
    match found.as_slice() {
        [] => Err(crate::Error::Unsupported(
            "free space: no filesystem this can map (HFS+, HFS, FAT, exFAT, ext2/3/4) found".into(),
        )),
        ["hfs+"] => hfs_plus(dev, &head),
        ["hfs"] => hfs(dev, &head),
        ["fat"] => fat(dev, &head),
        ["exfat"] => exfat(dev, &head),
        ["ext"] => ext(dev, &head),
        many => Err(crate::Error::InvalidImage(format!(
            "free space: signatures of several filesystems ({}) — refusing to guess",
            many.join(", ")
        ))),
    }
}

fn unsupported(what: &str) -> crate::Error {
    crate::Error::Unsupported(format!("free space: {what} volumes are not supported"))
}

fn not_clean(fs: &str, why: &str) -> crate::Error {
    crate::Error::InvalidImage(format!(
        "free space: {fs} volume {why} — mount and cleanly unmount it (or run fsck) first"
    ))
}

fn bad(fs: &str, why: impl core::fmt::Display) -> crate::Error {
    crate::Error::InvalidImage(format!("free space: {fs}: {why}"))
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}
fn be64(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(b[at..at + 8].try_into().unwrap())
}
fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// Accumulates free byte ranges in ascending order, merging neighbours.
struct Ranges(Vec<Range<u64>>);

impl Ranges {
    fn push(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        if let Some(last) = self.0.last_mut()
            && last.end >= start
        {
            last.end = last.end.max(end);
            return;
        }
        self.0.push(start..end);
    }

    /// Record the clear bits of `bitmap` as free units: bit `i` (counted
    /// from `first_bit`) is unit `first_bit + i`, at
    /// `base + unit × unit_size`. `msb_first` picks the bit order within a
    /// byte. Only units below `units` count.
    fn push_clear_bits(
        &mut self,
        bitmap: &[u8],
        first_bit: u64,
        msb_first: bool,
        units: u64,
        base: u64,
        unit_size: u64,
    ) {
        let n = ((bitmap.len() as u64) * 8).min(units.saturating_sub(first_bit));
        let mut i = 0u64;
        while i < n {
            let byte = bitmap[(i / 8) as usize];
            // Whole bytes at a time where they are uniform.
            if i.is_multiple_of(8) && i + 8 <= n && (byte == 0 || byte == 0xFF) {
                if byte == 0 {
                    let u = first_bit + i;
                    self.push(base + u * unit_size, base + (u + 8) * unit_size);
                }
                i += 8;
                continue;
            }
            let bit = (i % 8) as u32;
            let set = if msb_first {
                byte & (0x80 >> bit) != 0
            } else {
                byte & (1 << bit) != 0
            };
            if !set {
                let u = first_bit + i;
                self.push(base + u * unit_size, base + (u + 1) * unit_size);
            }
            i += 1;
        }
    }

    /// Clip everything to `[lo, hi)`.
    fn clip(mut self, lo: u64, hi: u64) -> Vec<Range<u64>> {
        self.0.retain_mut(|r| {
            r.start = r.start.max(lo);
            r.end = r.end.min(hi);
            r.start < r.end
        });
        self.0
    }
}

/// Read `len` bytes at `off`, refusing reads past the device.
fn read(dev: &mut dyn BlockDevice, off: u64, len: u64, fs: &str) -> Result<Vec<u8>> {
    if off.checked_add(len).is_none_or(|e| e > dev.total_size()) {
        return Err(bad(
            fs,
            format_args!("structure at {off:#x} lies past the volume"),
        ));
    }
    // Bound a single allocation: structures larger than this are read in
    // pieces by the callers.
    let mut v = vec![0u8; len as usize];
    dev.read_at(off, &mut v)?;
    Ok(v)
}

/// Bitmap reads are chunked to keep memory bounded on huge volumes.
const CHUNK: u64 = 1 << 20;

// ---------------------------------------------------------------------
// HFS+ / HFSX
// ---------------------------------------------------------------------

const HFS_UNMOUNTED: u32 = 1 << 8;
const HFS_INCONSISTENT: u32 = 1 << 11;
const HFS_JOURNALED: u32 = 1 << 13;

fn hfs_plus(dev: &mut dyn BlockDevice, head: &[u8]) -> Result<FreeSpace> {
    const FS: &str = "hfs+";
    let vh = &head[1024..1536];
    let version = be16(vh, 2);
    if !matches!(version, 4 | 5) {
        return Err(bad(FS, format_args!("volume header version {version}")));
    }
    let attrs = be32(vh, 4);
    if attrs & HFS_INCONSISTENT != 0 {
        return Err(not_clean(FS, "is marked inconsistent"));
    }
    if attrs & HFS_UNMOUNTED == 0 {
        return Err(not_clean(FS, "is mounted or was not cleanly unmounted"));
    }
    let block_size = be32(vh, 40) as u64;
    let total_blocks = be32(vh, 44) as u64;
    if block_size < 512 || !block_size.is_power_of_two() || total_blocks == 0 {
        return Err(bad(FS, "implausible block size or count"));
    }
    let volume_size = block_size * total_blocks;
    if volume_size > dev.total_size() {
        return Err(bad(
            FS,
            format_args!(
                "volume of {volume_size} bytes is larger than its device ({})",
                dev.total_size()
            ),
        ));
    }
    if attrs & HFS_JOURNALED != 0 {
        hfs_plus_journal_is_empty(dev, be32(vh, 12) as u64, block_size)?;
    }

    // The allocation file: its first 8 extents must hold the whole bitmap.
    let fork = &vh[112..112 + 80];
    let logical = be64(fork, 0);
    let need = total_blocks.div_ceil(8);
    if logical < need {
        return Err(bad(FS, "allocation file is smaller than the volume needs"));
    }
    let mut extents = Vec::new();
    let mut covered = 0u64;
    for i in 0..8 {
        let start = be32(fork, 16 + 8 * i) as u64;
        let count = be32(fork, 16 + 8 * i + 4) as u64;
        if count == 0 {
            break;
        }
        if start + count > total_blocks {
            return Err(bad(FS, "allocation file extent lies past the volume"));
        }
        extents.push((start, count));
        covered += count * block_size;
    }
    if covered < need {
        return Err(crate::Error::Unsupported(
            "free space: hfs+ allocation file continues in the extents overflow file".into(),
        ));
    }

    let mut out = Ranges(Vec::new());
    let mut bit = 0u64;
    'ext: for (start, count) in extents {
        let mut off = start * block_size;
        let mut left = count * block_size;
        while left > 0 && bit < total_blocks {
            let n = left.min(CHUNK).min((total_blocks - bit).div_ceil(8));
            let buf = read(dev, off, n, FS)?;
            out.push_clear_bits(&buf, bit, true, total_blocks, 0, block_size);
            bit += n * 8;
            off += n;
            left -= n;
        }
        if bit >= total_blocks {
            break 'ext;
        }
    }
    // The volume headers (and the boot blocks before the first one) are
    // never free, whatever a damaged bitmap says.
    let ranges = out.clip(1536, volume_size.min(dev.total_size() - 1024));
    Ok(FreeSpace {
        fs: FS,
        allocation_unit: block_size,
        volume_size,
        ranges,
    })
}

/// A journaled HFS+ volume is only consistent on disk once its journal is
/// empty (start == end).
fn hfs_plus_journal_is_empty(dev: &mut dyn BlockDevice, info_block: u64, bs: u64) -> Result<()> {
    const FS: &str = "hfs+";
    let jib = read(dev, info_block * bs, 52, FS)?;
    let flags = be32(&jib, 0);
    if flags & 2 != 0 {
        return Err(crate::Error::Unsupported(
            "free space: hfs+ journal on another device can't be checked".into(),
        ));
    }
    if flags & 1 == 0 {
        return Err(bad(FS, "journaled, but the journal is not in the volume"));
    }
    let off = be64(&jib, 36);
    let jh = read(dev, off, 32, FS)?;
    let (start, end) = if be32(&jh, 0) == 0x4A4E_4C78 && be32(&jh, 4) == 0x1234_5678 {
        (be64(&jh, 8), be64(&jh, 16))
    } else if le32(&jh, 0) == 0x4A4E_4C78 && le32(&jh, 4) == 0x1234_5678 {
        (le64(&jh, 8), le64(&jh, 16))
    } else {
        return Err(bad(FS, "journal header has no `JNLx` magic"));
    };
    if start != end {
        return Err(not_clean(FS, "has journal transactions not yet replayed"));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Classic HFS
// ---------------------------------------------------------------------

fn hfs(dev: &mut dyn BlockDevice, head: &[u8]) -> Result<FreeSpace> {
    const FS: &str = "hfs";
    let mdb = &head[1024..1536];
    if be16(mdb, 124) == u16::from_be_bytes(*b"H+") {
        return Err(unsupported("HFS+ embedded in an HFS wrapper"));
    }
    let attrs = be16(mdb, 10) as u32;
    if attrs & HFS_INCONSISTENT != 0 {
        return Err(not_clean(FS, "is marked inconsistent"));
    }
    if attrs & HFS_UNMOUNTED == 0 {
        return Err(not_clean(FS, "is mounted or was not cleanly unmounted"));
    }
    let bitmap_sector = be16(mdb, 14) as u64;
    let blocks = be16(mdb, 18) as u64;
    let block_size = be32(mdb, 20) as u64;
    let first = be16(mdb, 28) as u64 * 512;
    if block_size == 0 || !block_size.is_multiple_of(512) || blocks == 0 || bitmap_sector < 3 {
        return Err(bad(FS, "implausible allocation geometry"));
    }
    let volume_end = first + blocks * block_size;
    if volume_end + 1024 > dev.total_size() {
        return Err(bad(FS, "allocation blocks run past the device"));
    }
    let bitmap = read(dev, bitmap_sector * 512, blocks.div_ceil(8), FS)?;
    if bitmap_sector * 512 + bitmap.len() as u64 > first {
        return Err(bad(FS, "volume bitmap overlaps the allocation blocks"));
    }
    let mut out = Ranges(Vec::new());
    out.push_clear_bits(&bitmap, 0, true, blocks, first, block_size);
    // The volume ends with the alternate MDB and a reserved sector.
    let volume_size = volume_end + 1024;
    Ok(FreeSpace {
        fs: FS,
        allocation_unit: block_size,
        volume_size,
        ranges: out.clip(first, volume_end),
    })
}

// ---------------------------------------------------------------------
// FAT12 / FAT16 / FAT32
// ---------------------------------------------------------------------

struct Bpb {
    bps: u64,
    spc: u64,
    reserved: u64,
    fats: u64,
    root_entries: u64,
    total: u64,
    fat_size: u64,
    /// FAT32 `ext_flags`: bit 7 = mirroring off, bits 0-3 = active FAT.
    ext_flags: u16,
    fat32_layout: bool,
}

impl Bpb {
    fn parse(b: &[u8]) -> Option<Self> {
        if b[0] != 0xEB && b[0] != 0xE9 {
            return None;
        }
        let media = b[21];
        if media != 0xF0 && media < 0xF8 {
            return None;
        }
        let bps = le16(b, 11) as u64;
        let spc = b[13] as u64;
        let reserved = le16(b, 14) as u64;
        let fats = b[16] as u64;
        let root_entries = le16(b, 17) as u64;
        let total = match le16(b, 19) {
            0 => le32(b, 32) as u64,
            n => n as u64,
        };
        let (fat_size, fat32_layout) = match le16(b, 22) {
            0 => (le32(b, 36) as u64, true),
            n => (n as u64, false),
        };
        if !(512..=4096).contains(&bps)
            || !bps.is_power_of_two()
            || spc == 0
            || !spc.is_power_of_two()
            || reserved == 0
            || !(1..=2).contains(&fats)
            || total == 0
            || fat_size == 0
        {
            return None;
        }
        Some(Self {
            bps,
            spc,
            reserved,
            fats,
            root_entries,
            total,
            fat_size,
            ext_flags: if fat32_layout { le16(b, 40) } else { 0 },
            fat32_layout,
        })
    }
    fn data_start(&self) -> u64 {
        let root = (self.root_entries * 32).div_ceil(self.bps);
        (self.reserved + self.fats * self.fat_size + root) * self.bps
    }
    fn clusters(&self) -> u64 {
        (self.total * self.bps).saturating_sub(self.data_start()) / (self.spc * self.bps)
    }
    /// Entry width in bits, from the cluster count as the spec says.
    fn bits(&self) -> u64 {
        match self.clusters() {
            0..4085 => 12,
            4085..65525 => 16,
            _ => 32,
        }
    }
}

/// A plausible BPB whose first FAT entry carries the media byte.
fn fat_candidate(dev: &mut dyn BlockDevice, head: &[u8]) -> Result<bool> {
    let Some(bpb) = Bpb::parse(head) else {
        return Ok(false);
    };
    let at = bpb.reserved * bpb.bps;
    if at + 4 > dev.total_size() {
        return Ok(false);
    }
    let mut e = [0u8; 4];
    dev.read_at(at, &mut e)?;
    Ok(e[0] == head[21] && bpb.clusters() > 0)
}

fn fat(dev: &mut dyn BlockDevice, head: &[u8]) -> Result<FreeSpace> {
    let bpb = Bpb::parse(head).expect("checked by fat_candidate");
    let bits = bpb.bits();
    let fs = match bits {
        12 => "fat12",
        16 => "fat16",
        _ => "fat32",
    };
    if (bits == 32) != bpb.fat32_layout {
        return Err(bad(fs, "BPB layout does not match the cluster count"));
    }
    let volume_size = bpb.total * bpb.bps;
    if volume_size > dev.total_size() {
        return Err(bad(fs, "volume is larger than its device"));
    }
    let clusters = bpb.clusters();
    let entries = clusters + 2;
    let fat_bytes = bpb.fat_size * bpb.bps;
    if (entries * bits).div_ceil(8) > fat_bytes {
        return Err(bad(fs, "FAT is too small for the cluster count"));
    }
    // Which FAT copies to consult: the active one when FAT32 mirroring is
    // off, otherwise every copy (a cluster is free only if free in all).
    let copies: Vec<u64> = if bits == 32 && bpb.ext_flags & 0x80 != 0 {
        let active = (bpb.ext_flags & 0x0F) as u64;
        if active >= bpb.fats {
            return Err(bad(fs, "active FAT index past the FAT count"));
        }
        vec![active]
    } else {
        (0..bpb.fats).collect()
    };
    let fat_at = |c: u64| (bpb.reserved + c * bpb.fat_size) * bpb.bps;
    let entry = |t: &[u8], n: u64| -> u32 {
        match bits {
            12 => {
                let at = (n * 3 / 2) as usize;
                let v = le16(t, at) as u32;
                if n.is_multiple_of(2) {
                    v & 0xFFF
                } else {
                    v >> 4
                }
            }
            16 => le16(t, (n * 2) as usize) as u32,
            _ => le32(t, (n * 4) as usize) & 0x0FFF_FFFF,
        }
    };
    // Clean-shutdown and hard-error flags live in entry 1 (FAT16/32 only).
    if bits != 12 {
        let head = read(dev, fat_at(copies[0]), 8, fs)?;
        let (e1, clean, hard) = if bits == 16 {
            (le16(&head, 2) as u32, 0x8000, 0x4000)
        } else {
            (le32(&head, 4), 0x0800_0000, 0x0400_0000)
        };
        if e1 & clean != clean {
            return Err(not_clean(
                fs,
                "is marked dirty (mounted or not cleanly unmounted)",
            ));
        }
        if e1 & hard != hard {
            return Err(not_clean(fs, "recorded a disk I/O error"));
        }
    }
    let data = bpb.data_start();
    let csize = bpb.spc * bpb.bps;
    let mut out = Ranges(Vec::new());
    // A FAT12 table (6 KiB at most) in one piece, FAT16/32 in chunks.
    let step = if bits == 12 {
        entries
    } else {
        CHUNK * 8 / bits
    };
    let mut first = 0;
    while first < entries {
        let count = step.min(entries - first);
        let (off, len) = if bits == 12 {
            (0, (entries * bits).div_ceil(8))
        } else {
            (first * bits / 8, count * bits / 8)
        };
        let mut tables = Vec::new();
        for &c in &copies {
            tables.push(read(dev, fat_at(c) + off, len, fs)?);
        }
        for n in first.max(2)..first + count {
            let i = if bits == 12 { n } else { n - first };
            if tables.iter().all(|t| entry(t, i) == 0) {
                let at = data + (n - 2) * csize;
                out.push(at, at + csize);
            }
        }
        first += count;
    }
    Ok(FreeSpace {
        fs,
        allocation_unit: csize,
        volume_size,
        ranges: out.clip(data, volume_size),
    })
}

// ---------------------------------------------------------------------
// exFAT
// ---------------------------------------------------------------------

fn exfat(dev: &mut dyn BlockDevice, head: &[u8]) -> Result<FreeSpace> {
    const FS: &str = "exfat";
    let bps_shift = head[108] as u32;
    let spc_shift = head[109] as u32;
    if !(9..=12).contains(&bps_shift) || bps_shift + spc_shift > 25 {
        return Err(bad(FS, "implausible sector / cluster size"));
    }
    let bps = 1u64 << bps_shift;
    let csize = bps << spc_shift;
    let volume_size = le64(head, 72)
        .checked_mul(bps)
        .ok_or_else(|| bad(FS, "volume length overflows"))?;
    let fat_off = le32(head, 80) as u64 * bps;
    let fat_len = le32(head, 84) as u64 * bps;
    let heap = le32(head, 88) as u64 * bps;
    let clusters = le32(head, 92) as u64;
    let root = le32(head, 96);
    let flags = le16(head, 106);
    let fats = head[110];
    if flags & 0x2 != 0 {
        return Err(not_clean(
            FS,
            "is marked dirty (mounted or not cleanly unmounted)",
        ));
    }
    if flags & 0x4 != 0 {
        return Err(not_clean(FS, "recorded a media failure"));
    }
    if fats != 1 {
        return Err(unsupported("TexFAT (two-FAT) exFAT"));
    }
    if volume_size > dev.total_size()
        || heap + clusters * csize > volume_size
        || (clusters + 2) * 4 > fat_len
    {
        return Err(bad(FS, "geometry runs past the volume"));
    }
    let cluster_off = |c: u32| heap + (c as u64 - 2) * csize;
    let valid = |c: u32| c >= 2 && (c as u64) < clusters + 2;

    // Walk the root directory's cluster chain for the allocation bitmap.
    let mut bitmap: Option<(u32, u64)> = None;
    let mut c = root;
    let mut steps = 0u64;
    'dir: while valid(c) {
        steps += 1;
        if steps > clusters {
            return Err(bad(FS, "root directory cluster chain loops"));
        }
        let mut off = 0;
        while off < csize {
            let n = csize.min(CHUNK);
            let buf = read(dev, cluster_off(c) + off, n, FS)?;
            for e in buf.as_chunks::<32>().0 {
                match e[0] {
                    0x00 => break 'dir,
                    0x81 => {
                        if bitmap.is_some() {
                            return Err(bad(FS, "more than one allocation bitmap"));
                        }
                        bitmap = Some((le32(e, 20), le64(e, 24)));
                    }
                    _ => {}
                }
            }
            off += n;
        }
        let mut next = [0u8; 4];
        dev.read_at(fat_off + c as u64 * 4, &mut next)?;
        c = u32::from_le_bytes(next);
    }
    let (first, len) = bitmap.ok_or_else(|| bad(FS, "no allocation bitmap entry"))?;
    let need = clusters.div_ceil(8);
    if !valid(first) || len < need {
        return Err(bad(FS, "allocation bitmap entry is out of range"));
    }
    // The bitmap is contiguous (as the Linux and Windows drivers read it).
    let start = cluster_off(first);
    if start + need > heap + clusters * csize {
        return Err(bad(FS, "allocation bitmap runs past the cluster heap"));
    }
    let mut out = Ranges(Vec::new());
    let mut done = 0u64;
    while done < need {
        let n = (need - done).min(CHUNK);
        let buf = read(dev, start + done, n, FS)?;
        out.push_clear_bits(&buf, done * 8, false, clusters, heap, csize);
        done += n;
    }
    Ok(FreeSpace {
        fs: FS,
        allocation_unit: csize,
        volume_size,
        ranges: out.clip(heap, heap + clusters * csize),
    })
}

// ---------------------------------------------------------------------
// ext2 / ext3 / ext4
// ---------------------------------------------------------------------

fn ext(dev: &mut dyn BlockDevice, head: &[u8]) -> Result<FreeSpace> {
    const FS: &str = "ext";
    let sb = &head[1024..2048];
    let state = le16(sb, 58);
    let incompat = le32(sb, 96);
    let ro_compat = le32(sb, 100);
    if state & 1 == 0 {
        return Err(not_clean(FS, "is mounted or was not cleanly unmounted"));
    }
    if state & 2 != 0 {
        return Err(not_clean(FS, "has recorded errors"));
    }
    if incompat & 0x4 != 0 {
        return Err(not_clean(FS, "needs journal recovery"));
    }
    if incompat & 0x8 != 0 {
        return Err(unsupported("ext external-journal device"));
    }
    if incompat & 0x10 != 0 {
        return Err(unsupported("ext4 meta_bg"));
    }
    if ro_compat & 0x200 != 0 {
        return Err(unsupported("ext4 bigalloc"));
    }
    let log = le32(sb, 24);
    if log > 6 {
        return Err(bad(FS, "implausible block size"));
    }
    let bs = 1024u64 << log;
    let is64 = incompat & 0x80 != 0;
    let mut blocks = le32(sb, 4) as u64;
    if is64 {
        blocks |= (le32(sb, 336) as u64) << 32;
    }
    let first_data = le32(sb, 20) as u64;
    let per_group = le32(sb, 32) as u64;
    let desc_size = if is64 { le16(sb, 254) as u64 } else { 32 };
    if per_group == 0 || per_group > bs * 8 || blocks <= first_data || desc_size < 32 {
        return Err(bad(FS, "implausible geometry"));
    }
    if is64 && (desc_size < 64 || !desc_size.is_power_of_two() || desc_size > 1024) {
        return Err(bad(FS, "implausible group descriptor size"));
    }
    let volume_size = blocks
        .checked_mul(bs)
        .filter(|&s| s <= dev.total_size())
        .ok_or_else(|| bad(FS, "volume is larger than its device"))?;
    // Groups whose bitmap may be uninitialised (BLOCK_UNINIT) only exist
    // with group checksums; they are counted as used.
    let csums = ro_compat & (0x10 | 0x400) != 0;
    let groups = (blocks - first_data).div_ceil(per_group);
    let gdt = read(dev, (first_data + 1) * bs, groups * desc_size, FS)?;
    let mut out = Ranges(Vec::new());
    for g in 0..groups {
        let d = &gdt[(g * desc_size) as usize..((g + 1) * desc_size) as usize];
        let flags = le16(d, 18);
        if csums && flags & 0x2 != 0 {
            continue;
        }
        let mut bitmap_block = le32(d, 0) as u64;
        if is64 {
            bitmap_block |= (le32(d, 32) as u64) << 32;
        }
        if bitmap_block < first_data || bitmap_block >= blocks {
            return Err(bad(
                FS,
                format_args!("group {g} block bitmap at {bitmap_block}"),
            ));
        }
        let bm = read(dev, bitmap_block * bs, bs, FS)?;
        let start = first_data + g * per_group;
        let in_group = per_group.min(blocks - start);
        out.push_clear_bits(&bm, 0, false, in_group, start * bs, bs);
    }
    // Block 0 (boot sector + superblock) is never free.
    let lo = (first_data * bs).max(2048);
    Ok(FreeSpace {
        fs: FS,
        allocation_unit: bs,
        volume_size,
        ranges: out.clip(lo, volume_size),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;

    #[test]
    fn ranges_merge_and_bits() {
        let mut r = Ranges(Vec::new());
        // MSB-first: 0b1001_1111 → units 1, 2 free.
        r.push_clear_bits(&[0b1001_1111, 0x00], 0, true, 12, 100, 10);
        assert_eq!(r.0, vec![110..130, 180..220]);
        let mut r = Ranges(Vec::new());
        // LSB-first: 0b1111_1001 → units 1, 2 free.
        r.push_clear_bits(&[0b1111_1001], 0, false, 8, 0, 1);
        assert_eq!(r.0, vec![1..3]);
        assert_eq!(r.clip(2, 10), vec![2..3]);
    }

    #[test]
    fn unknown_and_ambiguous_refused() {
        let mut dev = MemoryBackend::new(64 * 1024);
        assert!(matches!(
            free_space(&mut dev),
            Err(crate::Error::Unsupported(_))
        ));
        // HFS+ and ext signatures at once.
        dev.write_at(1024, b"H+").unwrap();
        dev.write_at(1024 + 56, &0xEF53u16.to_le_bytes()).unwrap();
        assert!(matches!(
            free_space(&mut dev),
            Err(crate::Error::InvalidImage(_))
        ));
    }

    #[cfg(feature = "fat")]
    #[test]
    fn fat32_free_space_tracks_the_fat() {
        use crate::fs::Filesystem;
        let size = 64u64 << 20;
        let mut dev = MemoryBackend::new(size);
        let opts = crate::fs::fat::FatFormatOpts {
            total_sectors: (size / 512) as u32,
            volume_id: 1,
            volume_label: *b"FREE       ",
            ..Default::default()
        };
        let mut fs = crate::fs::fat::Fat32::format(&mut dev, &opts).unwrap();
        fs.flush(&mut dev).unwrap();
        let empty = free_space(&mut dev).unwrap();
        assert_eq!(empty.fs, "fat32");
        let free0 = empty.free_bytes();
        assert!(free0 > size / 2);
        let data = vec![0x5Au8; 3 << 20];
        let mut fs = crate::fs::fat::Fat32::open(&mut dev).unwrap();
        fs.create_file(
            &mut dev,
            std::path::Path::new("/big"),
            crate::fs::FileSource::Reader {
                reader: Box::new(std::io::Cursor::new(data.clone())),
                len: data.len() as u64,
            },
            crate::fs::FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();
        let after = free_space(&mut dev).unwrap();
        assert!(free0 - after.free_bytes() >= data.len() as u64);
        // None of the file's bytes are in a free range.
        let mut hits = 0u64;
        for r in &after.ranges {
            let mut b = vec![0u8; (r.end - r.start) as usize];
            dev.read_at(r.start, &mut b).unwrap();
            hits += b.iter().filter(|&&x| x == 0x5A).count() as u64;
        }
        assert_eq!(hits, 0);
        // A dirty volume is refused.
        let e1 = 512 * 32 + 4; // reserved = 32 sectors, entry 1
        let mut v = [0u8; 4];
        dev.read_at(e1, &mut v).unwrap();
        let dirty = (u32::from_le_bytes(v) & !0x0800_0000).to_le_bytes();
        dev.write_at(e1, &dirty).unwrap();
        assert!(matches!(
            free_space(&mut dev),
            Err(crate::Error::InvalidImage(_))
        ));
    }

    /// Count 512-byte sectors inside `ranges` filled entirely with `b`.
    #[cfg(all(
        feature = "std",
        any(
            feature = "fat",
            feature = "ext",
            feature = "hfs-plus",
            feature = "hfs",
            feature = "exfat"
        )
    ))]
    fn sectors_of(dev: &mut dyn BlockDevice, ranges: &[Range<u64>], b: u8) -> u64 {
        let mut n = 0;
        for r in ranges {
            let mut buf = vec![0u8; (r.end - r.start) as usize];
            dev.read_at(r.start, &mut buf).unwrap();
            n += buf
                .as_chunks::<512>()
                .0
                .iter()
                .filter(|c| c.iter().all(|&x| x == b))
                .count() as u64;
        }
        n
    }

    /// Format, add a file to keep and one to delete, delete it, flush:
    /// the deleted file's bytes must (almost all) be in free ranges, the
    /// kept one's never.
    #[cfg(all(
        feature = "std",
        any(
            feature = "fat",
            feature = "ext",
            feature = "hfs-plus",
            feature = "hfs",
            feature = "exfat"
        )
    ))]
    fn keep_and_delete(dev: &mut dyn BlockDevice, want_fs: &str) {
        use crate::inspect::AnyFs;
        let d = tempfile::tempdir().unwrap();
        let keep = d.path().join("keep");
        let gone = d.path().join("gone");
        std::fs::write(&keep, vec![0x5Au8; 1 << 20]).unwrap();
        std::fs::write(&gone, vec![0xC3u8; 2 << 20]).unwrap();
        let free0 = free_space(dev).unwrap();
        assert_eq!(free0.fs, want_fs);
        let mut fs = AnyFs::open_writable(dev).unwrap();
        fs.add_file(dev, "/keep", &keep).unwrap();
        fs.add_file(dev, "/gone", &gone).unwrap();
        fs.flush(dev).unwrap();
        drop(fs);
        let full = free_space(dev).unwrap();
        assert!(
            free0.free_bytes() - full.free_bytes() >= 3 << 20,
            "{want_fs}"
        );
        let mut fs = AnyFs::open_writable(dev).unwrap();
        fs.remove(dev, "/gone").unwrap();
        fs.flush(dev).unwrap();
        drop(fs);
        let after = free_space(dev).unwrap();
        assert!(
            after.free_bytes() - full.free_bytes() >= 2 << 20,
            "{want_fs}"
        );
        assert_eq!(
            sectors_of(dev, &after.ranges, 0x5A),
            0,
            "{want_fs}: kept data free"
        );
        let gone_free = sectors_of(dev, &after.ranges, 0xC3);
        assert!(
            gone_free >= (2 << 20) / 512,
            "{want_fs}: {gone_free} sectors"
        );
        for w in after.ranges.windows(2) {
            assert!(w[0].end < w[1].start, "{want_fs}: unsorted / unmerged");
        }
        assert!(after.ranges.last().unwrap().end <= after.volume_size);
    }

    #[cfg(all(feature = "std", feature = "fat"))]
    #[test]
    fn fat16_keep_and_delete() {
        let mut dev = MemoryBackend::new(32 << 20);
        let opts = crate::fs::fat::FatFormatOpts {
            kind: crate::fs::fat::FatKind::Fat16,
            total_sectors: (32 << 20) / 512,
            volume_id: 2,
            volume_label: *b"FREE       ",
            ..Default::default()
        };
        let _ = crate::fs::fat::Fat32::format(&mut dev, &opts).unwrap();
        keep_and_delete(&mut dev, "fat16");
    }

    #[cfg(all(feature = "std", feature = "ext"))]
    #[test]
    fn ext_keep_and_delete() {
        use crate::fs::ext::{Ext, FormatOpts, FsKind};
        for (kind, flex) in [(FsKind::Ext2, 0), (FsKind::Ext4, 4)] {
            let mut opts = FormatOpts {
                kind,
                block_size: 4096,
                blocks_count: 4096,
                inodes_count: 256,
                ..Default::default()
            };
            opts.log_groups_per_flex = flex;
            let mut dev = MemoryBackend::new(16 << 20);
            let mut fs = Ext::format_with(&mut dev, &opts).unwrap();
            crate::fs::Filesystem::flush(&mut fs, &mut dev).unwrap();
            drop(fs);
            keep_and_delete(&mut dev, "ext");
        }
    }

    #[cfg(all(feature = "std", feature = "hfs-plus"))]
    #[test]
    fn hfs_plus_keep_and_delete() {
        use crate::fs::hfs_plus::{FormatOpts, HfsPlus};
        let mut dev = MemoryBackend::new(32 << 20);
        let mut fs = HfsPlus::format(&mut dev, &FormatOpts::default()).unwrap();
        crate::fs::Filesystem::flush(&mut fs, &mut dev).unwrap();
        drop(fs);
        keep_and_delete(&mut dev, "hfs+");
        // A volume marked mounted is refused.
        let mut a = [0u8; 4];
        dev.read_at(1028, &mut a).unwrap();
        let v = u32::from_be_bytes(a) & !HFS_UNMOUNTED;
        dev.write_at(1028, &v.to_be_bytes()).unwrap();
        assert!(matches!(
            free_space(&mut dev),
            Err(crate::Error::InvalidImage(_))
        ));
    }

    #[cfg(all(feature = "std", feature = "hfs"))]
    #[test]
    fn hfs_keep_and_delete() {
        use crate::fs::hfs::{Hfs, HfsFormatOpts};
        let mut dev = MemoryBackend::new(32 << 20);
        let mut fs = Hfs::format(&mut dev, &HfsFormatOpts::default()).unwrap();
        crate::fs::Filesystem::flush(&mut fs, &mut dev).unwrap();
        drop(fs);
        keep_and_delete(&mut dev, "hfs");
    }

    #[cfg(all(feature = "std", feature = "exfat"))]
    #[test]
    fn exfat_keep_and_delete() {
        use crate::fs::exfat::{Exfat, FormatOpts};
        let mut dev = MemoryBackend::new(32 << 20);
        let fs = Exfat::format(&mut dev, &FormatOpts::default()).unwrap();
        drop(fs);
        keep_and_delete(&mut dev, "exfat");
        // A dirty volume is refused.
        let mut f = [0u8; 2];
        dev.read_at(106, &mut f).unwrap();
        dev.write_at(106, &(u16::from_le_bytes(f) | 2).to_le_bytes())
            .unwrap();
        assert!(matches!(
            free_space(&mut dev),
            Err(crate::Error::InvalidImage(_))
        ));
    }
}
