//! Read-only HFS+ / HFSX verification — a bounded `fsck_hfs -n`.
//!
//! [`verify`] reads the volume without writing anything and returns a
//! [`VerifyReport`] of structured [`crate::fs::verify::Diagnostic`]s.
//! What it checks, in order:
//!
//! 1. **Volume headers.** The primary at byte 1024 (signature/version,
//!    block size, block count against the device, the clean-unmount and
//!    inconsistent flags) and the alternate in the second-to-last
//!    512-byte sector of the device — and, when the volume does not
//!    fill its device, of the volume — compared field by field on what
//!    must agree (block size, block count, special-file extents).
//! 2. **Journal** (journaled volumes): the info block, an in-volume
//!    journal with a valid header, and whether it is empty.
//! 3. **Special files**: the extents-overflow, catalog, attributes,
//!    allocation and startup forks — extents in range, block counts
//!    matching, logical sizes within their physical size, overflow
//!    extents (special forks other than the extents file itself may
//!    continue in the extents-overflow tree) contiguous.
//! 4. **B-trees** (extents overflow, catalog, attributes): header node
//!    and header record, node descriptors (kind and height per level),
//!    record-offset tables, key validity and strictly ascending order
//!    within and across nodes, index keys equal to their child's first
//!    key, sibling links per level, tree depth, leaf count and
//!    first/last leaf, and the node-allocation map against the nodes
//!    actually reachable.
//! 5. **Catalog semantics**: each file and folder has a matching thread
//!    record (and every thread a record), unique CNIDs below
//!    `nextCatalogID` (unless the CNIDs-reused flag is set) and outside
//!    the reserved range, folder valences, the header's file and folder
//!    counts, every record's parent existing, the root folder, and hard
//!    link counts against the indirect-node files.
//! 6. **Extents-overflow and attribute records** refer to forks and
//!    files that exist and are contiguous.
//! 7. **Allocation**: every extent claimed by the special files, the
//!    catalog's data and resource forks, extent-based attributes, the
//!    bad-block file and the reserved areas (boot blocks + primary
//!    header at the start, alternate header at the end) is collected
//!    into a computed bitmap; overlaps are reported as they are found,
//!    and the computed bitmap is compared with the on-disk one (blocks
//!    leaked, blocks in use but marked free) and with the header's
//!    `freeBlocks`.
//!
//! All walks are bounded by [`VerifyOpts`]; see [`crate::fs::verify`].
//! On a journaled volume whose journal holds transactions the report
//! describes the pre-replay state and carries a
//! [`DiagCode::JournalNotEmpty`] warning.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use crate::Result;
use crate::block::BlockDevice;
use crate::fs::verify::{Collector, DiagCode, Location, Truncation, VerifyOpts, VerifyReport};

use super::attributes::AttrKey;
use super::btree::{
    BTreeHeader, ForkReader, HEADER_REC_SIZE, KIND_HEADER, KIND_INDEX, KIND_LEAF,
    NODE_DESCRIPTOR_SIZE, NodeDescriptor, record_offsets,
};
use super::catalog::{
    CatalogKey, CatalogRecord, KEY_COMPARE_BINARY, REC_FILE, REC_FILE_THREAD, REC_FOLDER,
    REC_FOLDER_THREAD, ROOT_FOLDER_ID, ROOT_PARENT_ID,
};
use super::extents::{ExtentKey, decode_extent_record};
use super::volume_header::{ExtentDescriptor, FORK_DATA_SIZE, ForkData, SIG_HFS_PLUS, SIG_HFSX};

/// `kHFSVolumeUnmountedBit`.
const ATTR_UNMOUNTED: u32 = 1 << 8;
/// `kHFSVolumeInconsistentBit`.
const ATTR_INCONSISTENT: u32 = 1 << 11;
/// `kHFSCatalogNodeIDsReusedBit`.
const ATTR_CNIDS_REUSED: u32 = 1 << 12;
/// `kHFSVolumeJournaledBit`.
const ATTR_JOURNALED: u32 = 1 << 13;

/// `kBTVariableIndexKeysMask`.
const BT_VARIABLE_INDEX_KEYS: u32 = 1 << 2;
/// Node kind `kBTMapNode`.
const KIND_MAP: i8 = 2;

/// Reserved CNIDs.
const CNID_EXTENTS: u32 = 3;
const CNID_CATALOG: u32 = 4;
const CNID_BAD_BLOCKS: u32 = 5;
const CNID_ALLOCATION: u32 = 6;
const CNID_STARTUP: u32 = 7;
const CNID_ATTRIBUTES: u32 = 8;
/// `kHFSFirstUserCatalogNodeID`.
const FIRST_USER_CNID: u32 = 16;

/// Attribute record types.
const ATTR_INLINE: u32 = 0x10;
const ATTR_FORK: u32 = 0x20;
const ATTR_EXTENTS: u32 = 0x30;

/// Name of the hard-link private directory, `"\0\0\0\0HFS+ Private Data"`.
fn private_dir_name() -> Vec<u16> {
    let mut v = vec![0u16; 4];
    v.extend("HFS+ Private Data".encode_utf16());
    v
}

/// Verify the HFS+ or HFSX volume on `dev` (which must start at the
/// volume: slice a partition first). Never writes.
///
/// Returns `Err` only when the device cannot be read at all; anything
/// wrong with the volume itself — including a primary header that does
/// not decode — is reported as diagnostics.
pub fn verify(dev: &mut dyn BlockDevice, opts: &VerifyOpts) -> Result<VerifyReport> {
    let mut v = Verifier::new(dev, opts);
    v.run()?;
    Ok(v.c.finish())
}

/// Which B-tree a walk is over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tree {
    Extents,
    Catalog,
    Attributes,
}

impl Tree {
    fn name(self) -> &'static str {
        match self {
            Tree::Extents => "extents-overflow",
            Tree::Catalog => "catalog",
            Tree::Attributes => "attributes",
        }
    }

    fn max_key_length(self) -> u16 {
        match self {
            Tree::Extents => 10,
            Tree::Catalog => 516,
            Tree::Attributes => 266,
        }
    }
}

/// A decoded key of any of the three trees.
#[derive(Debug, Clone)]
enum Key {
    Cat(CatalogKey),
    Ext(ExtentKey),
    Attr(AttrKey),
}

/// One extents-overflow leaf record: its starting fork block and its
/// eight extents.
type OverflowRecord = (u32, [ExtentDescriptor; 8]);

/// What the catalog walk remembers per CNID.
#[derive(Debug, Clone, Copy)]
struct RecInfo {
    parent: u32,
    name_hash: u64,
    folder: bool,
    valence: u32,
}

#[derive(Debug, Clone, Copy)]
struct ThreadInfo {
    parent: u32,
    name_hash: u64,
    folder: bool,
}

/// An extent-based attribute being followed across its 0x20 record and
/// any 0x30 continuation records.
struct OpenAttrFork {
    file_id: u32,
    name: Vec<u16>,
    total_blocks: u64,
    covered: u64,
    logical_size: u64,
}

fn name_hash(units: &[u16]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &u in units {
        for b in u.to_be_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}
fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(b[o..o + 4].try_into().unwrap())
}
fn be64(b: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(b[o..o + 8].try_into().unwrap())
}

fn fork_at(vh: &[u8; 512], off: usize) -> ForkData {
    let mut tmp = [0u8; FORK_DATA_SIZE];
    tmp.copy_from_slice(&vh[off..off + FORK_DATA_SIZE]);
    ForkData::decode(&tmp)
}

/// Offsets of the five special-file fork records in a volume header.
const FORK_ALLOCATION: usize = 0x70;
const FORK_EXTENTS: usize = 0xC0;
const FORK_CATALOG: usize = 0x110;
const FORK_ATTRIBUTES: usize = 0x160;
const FORK_STARTUP: usize = 0x1B0;

struct Verifier<'d> {
    c: Collector,
    dev: &'d mut dyn BlockDevice,
    vh: [u8; 512],
    bs: u64,
    total: u64,
    hfsx: bool,
    case_sensitive: bool,
    /// Computed allocation map, one bit per block (MSB first, like the
    /// on-disk bitmap). `None` when it would exceed the memory bound.
    claimed: Option<Vec<u8>>,
    /// Blocks reserved by the format: (start, count) runs.
    reserved: Vec<(u64, u64)>,
    /// Extents-overflow records: (forkType, fileID) → (startBlock, extents).
    overflow: HashMap<(u8, u32), Vec<OverflowRecord>>,
    /// Overflow keys consumed by a fork.
    overflow_used: HashSet<(u8, u32)>,
    /// Catalog: CNID → record summary.
    recs: HashMap<u32, RecInfo>,
    threads: HashMap<u32, ThreadInfo>,
    children: HashMap<u32, u32>,
    files: u64,
    folders: u64,
    /// Hard links: inode number → links seen.
    link_refs: HashMap<u32, u32>,
    /// Indirect-node files: (parent, inode number, link count, cnid).
    inodes: Vec<(u32, u32, u32, u32)>,
    private_dir: Option<u32>,
    open_attr: Option<OpenAttrFork>,
    /// A walk was cut short somewhere; whole-volume cross-checks that
    /// need complete information are skipped.
    incomplete: bool,
}

impl<'d> Verifier<'d> {
    fn new(dev: &'d mut dyn BlockDevice, opts: &VerifyOpts) -> Self {
        Self {
            c: Collector::new("hfs+", opts),
            dev,
            vh: [0u8; 512],
            bs: 0,
            total: 0,
            hfsx: false,
            case_sensitive: false,
            claimed: None,
            reserved: Vec::new(),
            overflow: HashMap::new(),
            overflow_used: HashSet::new(),
            recs: HashMap::new(),
            threads: HashMap::new(),
            children: HashMap::new(),
            files: 0,
            folders: 0,
            link_refs: HashMap::new(),
            inodes: Vec::new(),
            private_dir: None,
            open_attr: None,
            incomplete: false,
        }
    }

    fn run(&mut self) -> Result<()> {
        if !self.check_header()? {
            return Ok(());
        }
        self.check_alternate()?;
        self.check_journal()?;

        // Reserved areas: the boot blocks and the primary header at the
        // start, the alternate header (and the last sector) at the end.
        let head = 1536u64.div_ceil(self.bs);
        let tail = 1024u64.div_ceil(self.bs);
        self.reserved = vec![
            (0, head.min(self.total)),
            (self.total.saturating_sub(tail), tail.min(self.total)),
        ];
        for (s, n) in self.reserved.clone() {
            self.claim(s, n, 0, "reserved area");
        }

        // 1. The extents-overflow file: its own extents are inline only.
        let ext_fork = fork_at(&self.vh, FORK_EXTENTS);
        let ext_extents = self.fork_extents(&ext_fork, CNID_EXTENTS, 0, "extents-overflow file");
        if let Some(ext) = &ext_extents {
            for e in ext.clone() {
                self.claim(
                    u64::from(e.start_block),
                    u64::from(e.block_count),
                    CNID_EXTENTS,
                    "extents-overflow file",
                );
            }
        }
        if let Some(ext) = ext_extents
            && ext_fork.total_blocks > 0
        {
            self.walk_tree(Tree::Extents, &ext_fork, ext)?;
        }

        // 2. The remaining special files (may continue in the overflow tree).
        let mut catalog_extents = None;
        let mut attributes_extents = None;
        let mut allocation_extents = None;
        for (off, cnid, what) in [
            (FORK_ALLOCATION, CNID_ALLOCATION, "allocation file"),
            (FORK_CATALOG, CNID_CATALOG, "catalog file"),
            (FORK_ATTRIBUTES, CNID_ATTRIBUTES, "attributes file"),
            (FORK_STARTUP, CNID_STARTUP, "startup file"),
        ] {
            let fork = fork_at(&self.vh, off);
            let ext = self.fork_extents(&fork, cnid, 0, what);
            if let Some(list) = &ext {
                for e in list.clone() {
                    self.claim(
                        u64::from(e.start_block),
                        u64::from(e.block_count),
                        cnid,
                        what,
                    );
                }
            }
            match cnid {
                CNID_CATALOG => catalog_extents = ext,
                CNID_ATTRIBUTES => attributes_extents = ext,
                CNID_ALLOCATION => allocation_extents = ext,
                _ => {}
            }
        }

        // 3. The catalog.
        let cat_fork = fork_at(&self.vh, FORK_CATALOG);
        match catalog_extents {
            Some(ext) if cat_fork.total_blocks > 0 => {
                self.walk_tree(Tree::Catalog, &cat_fork, ext)?;
                self.check_catalog_semantics();
            }
            _ => self.c.error(
                DiagCode::RootMissing,
                Location::structure("catalog"),
                "the volume has no usable catalog file",
            ),
        }

        // 4. Attributes.
        let attr_fork = fork_at(&self.vh, FORK_ATTRIBUTES);
        if let Some(ext) = attributes_extents
            && attr_fork.total_blocks > 0
        {
            self.walk_tree(Tree::Attributes, &attr_fork, ext)?;
            self.close_attr_fork();
        }

        // 5. Bad-block file and orphaned overflow records.
        self.check_overflow_leftovers();

        // 6. Allocation bitmap.
        if let Some(ext) = allocation_extents {
            self.check_bitmap(&fork_at(&self.vh, FORK_ALLOCATION), ext)?;
        }

        self.c.report.stats.files = self.files;
        self.c.report.stats.folders = self.folders;
        self.c.report.stats.total_blocks = self.total;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Volume headers
    // ------------------------------------------------------------------

    /// Check the primary header. Returns false when nothing else can be
    /// checked.
    fn check_header(&mut self) -> Result<bool> {
        let size = self.dev.total_size();
        let loc = || Location::structure("volume-header").at_byte(1024);
        if size < 1536 {
            self.c.error(
                DiagCode::HeaderUnreadable,
                loc(),
                format!("device of {size} bytes is too small for an HFS+ volume header"),
            );
            return Ok(false);
        }
        self.dev.read_at(1024, &mut self.vh)?;
        let sig = [self.vh[0], self.vh[1]];
        if sig != SIG_HFS_PLUS && sig != SIG_HFSX {
            self.c.error(
                DiagCode::HeaderUnreadable,
                loc(),
                format!(
                    "bad volume signature {:02x}{:02x} (expected 'H+' or 'HX')",
                    sig[0], sig[1]
                ),
            );
            return Ok(false);
        }
        self.hfsx = sig == SIG_HFSX;
        if self.hfsx {
            self.c.report.fs = "hfsx";
        }
        let version = be16(&self.vh, 2);
        let want = if self.hfsx { 5 } else { 4 };
        if version != want {
            self.c.error(
                DiagCode::HeaderFieldInvalid,
                loc(),
                format!("volume header version {version}, expected {want}"),
            );
        }
        let attrs = be32(&self.vh, 4);
        if attrs & ATTR_INCONSISTENT != 0 {
            self.c.error(
                DiagCode::VolumeInconsistent,
                loc(),
                "the volume is flagged inconsistent (kHFSVolumeInconsistentBit)",
            );
        }
        if attrs & ATTR_UNMOUNTED == 0 {
            self.c.warn(
                DiagCode::VolumeDirty,
                loc(),
                "the volume is not marked cleanly unmounted",
            );
        }
        let bs = be32(&self.vh, 40);
        if bs < 512 || !bs.is_power_of_two() {
            self.c.error(
                DiagCode::HeaderFieldInvalid,
                loc(),
                format!("block size {bs} is not a power of two >= 512"),
            );
            return Ok(false);
        }
        self.bs = u64::from(bs);
        self.total = u64::from(be32(&self.vh, 44));
        if self.total == 0 {
            self.c
                .error(DiagCode::HeaderFieldInvalid, loc(), "totalBlocks is zero");
            return Ok(false);
        }
        let vol_bytes = self.total * self.bs;
        if vol_bytes > size {
            self.c.error(
                DiagCode::VolumeLargerThanDevice,
                loc(),
                format!(
                    "volume of {} blocks x {} bytes = {vol_bytes} bytes exceeds its \
                     {size}-byte device",
                    self.total, self.bs
                ),
            );
            return Ok(false);
        }
        let free = u64::from(be32(&self.vh, 48));
        if free > self.total {
            self.c.error(
                DiagCode::FreeCountMismatch,
                loc(),
                format!("freeBlocks {free} exceeds totalBlocks {}", self.total),
            );
        }
        let bitmap_bytes = self.total.div_ceil(8);
        if bitmap_bytes <= self.c.opts.max_bitmap_bytes {
            self.claimed = Some(vec![0u8; bitmap_bytes as usize]);
        } else {
            self.c.report.truncate(Truncation::Memory);
            self.c.info(
                DiagCode::Unsupported,
                Location::structure("allocation-bitmap"),
                format!(
                    "allocation cross-check skipped: needs {bitmap_bytes} bytes, \
                     max_bitmap_bytes is {}",
                    self.c.opts.max_bitmap_bytes
                ),
            );
        }
        Ok(true)
    }

    /// Compare the alternate header(s) with the primary.
    fn check_alternate(&mut self) -> Result<()> {
        let size = self.dev.total_size();
        let dev_loc = size - 1024;
        let fs_loc = self.total * self.bs - 1024;
        let mut locs = vec![dev_loc];
        if fs_loc != dev_loc {
            locs.push(fs_loc);
        }
        let mut any_ok = false;
        let mut problems: Vec<(u64, String)> = Vec::new();
        for off in locs {
            let mut alt = [0u8; 512];
            self.dev.read_at(off, &mut alt)?;
            match self.compare_alternate(&alt) {
                Ok(()) => any_ok = true,
                Err(why) => problems.push((off, why)),
            }
        }
        for (off, why) in problems {
            let loc = Location::structure("alternate-volume-header").at_byte(off);
            let missing = why.starts_with("missing");
            // One good copy (at either the device- or the volume-relative
            // location) is what the kernel needs; the other is a warning.
            let sev_error = !any_ok;
            let code = if missing {
                DiagCode::AlternateHeaderMissing
            } else {
                DiagCode::AlternateHeaderMismatch
            };
            if sev_error {
                self.c.error(code, loc, why);
            } else {
                self.c.warn(code, loc, why);
            }
        }
        Ok(())
    }

    fn compare_alternate(&self, alt: &[u8; 512]) -> std::result::Result<(), String> {
        if alt[0..2] != self.vh[0..2] {
            return Err(format!(
                "missing or bad signature {:02x}{:02x}",
                alt[0], alt[1]
            ));
        }
        for (off, what) in [(40usize, "blockSize"), (44, "totalBlocks")] {
            if alt[off..off + 4] != self.vh[off..off + 4] {
                return Err(format!(
                    "{what} {} differs from the primary's {}",
                    be32(alt, off),
                    be32(&self.vh, off)
                ));
            }
        }
        for (off, what) in [
            (FORK_ALLOCATION, "allocation file"),
            (FORK_EXTENTS, "extents-overflow file"),
            (FORK_CATALOG, "catalog file"),
            (FORK_ATTRIBUTES, "attributes file"),
            (FORK_STARTUP, "startup file"),
        ] {
            // totalBlocks + the eight extents.
            if alt[off + 12..off + 80] != self.vh[off + 12..off + 80] {
                return Err(format!("{what} extents differ from the primary's"));
            }
        }
        Ok(())
    }

    fn check_journal(&mut self) -> Result<()> {
        let attrs = be32(&self.vh, 4);
        if attrs & ATTR_JOURNALED == 0 {
            return Ok(());
        }
        let loc = || Location::structure("journal");
        let jib_block = u64::from(be32(&self.vh, 12));
        if jib_block == 0 || jib_block >= self.total {
            self.c.error(
                DiagCode::JournalInvalid,
                loc(),
                format!("journalInfoBlock {jib_block} is outside the volume"),
            );
            return Ok(());
        }
        let mut jib = [0u8; 52];
        self.dev.read_at(jib_block * self.bs, &mut jib)?;
        let flags = be32(&jib, 0);
        if flags & 2 != 0 {
            self.c.info(
                DiagCode::Unsupported,
                loc(),
                "the journal lives on another device and was not checked",
            );
            return Ok(());
        }
        if flags & 1 == 0 {
            self.c.error(
                DiagCode::JournalInvalid,
                loc(),
                "journaled, but the journal info block does not place the journal in the volume",
            );
            return Ok(());
        }
        let off = be64(&jib, 36);
        let jsize = be64(&jib, 44);
        let vol = self.total * self.bs;
        if off.checked_add(jsize).is_none_or(|e| e > vol) || jsize < 512 {
            self.c.error(
                DiagCode::JournalInvalid,
                loc().at_byte(off),
                format!("journal at byte {off} (+{jsize}) lies outside the volume"),
            );
            return Ok(());
        }
        let mut jh = [0u8; 32];
        self.dev.read_at(off, &mut jh)?;
        let (start, end) = if be32(&jh, 0) == 0x4A4E_4C78 && be32(&jh, 4) == 0x1234_5678 {
            (be64(&jh, 8), be64(&jh, 16))
        } else if jh[0..4] == 0x4A4E_4C78u32.to_le_bytes()
            && jh[4..8] == 0x1234_5678u32.to_le_bytes()
        {
            (
                u64::from_le_bytes(jh[8..16].try_into().unwrap()),
                u64::from_le_bytes(jh[16..24].try_into().unwrap()),
            )
        } else {
            self.c.error(
                DiagCode::JournalInvalid,
                loc().at_byte(off),
                "journal header has no JNLx magic",
            );
            return Ok(());
        };
        if start != end {
            self.c.warn(
                DiagCode::JournalNotEmpty,
                loc().at_byte(off),
                format!(
                    "the journal holds unreplayed transactions (start {start}, end {end}); \
                     this report describes the on-disk state before replay"
                ),
            );
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Allocation
    // ------------------------------------------------------------------

    /// Mark `[start, start+count)` as owned by `owner`, reporting blocks
    /// past the end and blocks already claimed.
    fn claim(&mut self, start: u64, count: u64, owner: u32, what: &str) {
        if count == 0 {
            return;
        }
        let end = start.saturating_add(count);
        if end > self.total {
            self.c.error(
                DiagCode::ExtentOutOfRange,
                Location::structure("allocation")
                    .blocks(start, count)
                    .object(u64::from(owner)),
                format!(
                    "{what} extent {start}+{count} reaches past the last block {}",
                    self.total
                ),
            );
        }
        let Some(map) = self.claimed.as_mut() else {
            return;
        };
        let stop = end.min(self.total);
        let mut dup_first = None;
        let mut dup_count = 0u64;
        let mut b = start;
        while b < stop {
            let byte = (b / 8) as usize;
            // Whole-byte fast path.
            if b.is_multiple_of(8) && b + 8 <= stop {
                if map[byte] != 0 {
                    dup_first.get_or_insert(b + u64::from(map[byte].leading_zeros()));
                    dup_count += u64::from(map[byte].count_ones());
                }
                map[byte] = 0xFF;
                b += 8;
                continue;
            }
            let mask = 0x80u8 >> (b % 8);
            if map[byte] & mask != 0 {
                dup_first.get_or_insert(b);
                dup_count += 1;
            }
            map[byte] |= mask;
            b += 1;
        }
        if let Some(first) = dup_first {
            self.c.error(
                DiagCode::ExtentOverlap,
                Location::structure("allocation")
                    .blocks(first, dup_count)
                    .object(u64::from(owner)),
                format!(
                    "{what} (CNID {owner}) extent {start}+{count} overlaps {dup_count} \
                     block(s) already in use, first {first}"
                ),
            );
        }
    }

    /// Collect a fork's full extent list (inline + overflow), checking it
    /// against the fork's block count and logical size. `None` when the
    /// list is unusable.
    fn fork_extents(
        &mut self,
        fork: &ForkData,
        cnid: u32,
        fork_type: u8,
        what: &str,
    ) -> Option<Vec<ExtentDescriptor>> {
        let loc = || Location::structure("fork").object(u64::from(cnid));
        let mut out = Vec::new();
        let mut sum = 0u64;
        let mut ended = false;
        for e in fork.extents {
            if e.block_count == 0 {
                ended = true;
                continue;
            }
            if ended {
                self.c.error(
                    DiagCode::ForkExtentsInvalid,
                    loc(),
                    format!("{what}: a non-empty extent follows an empty one"),
                );
                return None;
            }
            if !self.c.take_extent() {
                self.incomplete = true;
                return None;
            }
            sum += u64::from(e.block_count);
            out.push(e);
        }
        let want = u64::from(fork.total_blocks);
        if sum < want && cnid != CNID_EXTENTS {
            // Continue in the extents-overflow tree.
            let key = (fork_type, cnid);
            if let Some(recs) = self.overflow.get(&key).cloned() {
                self.overflow_used.insert(key);
                for (start, exts) in recs {
                    if u64::from(start) != sum {
                        self.c.error(
                            DiagCode::ForkExtentsInvalid,
                            Location::structure("extents-overflow").object(u64::from(cnid)),
                            format!(
                                "{what}: overflow record starts at fork block {start}, \
                                 expected {sum}"
                            ),
                        );
                        return None;
                    }
                    for e in exts {
                        if e.block_count == 0 {
                            break;
                        }
                        if !self.c.take_extent() {
                            self.incomplete = true;
                            return None;
                        }
                        sum += u64::from(e.block_count);
                        out.push(e);
                    }
                }
            }
        }
        if sum != want {
            self.c.error(
                DiagCode::ForkSizeMismatch,
                loc(),
                format!("{what}: totalBlocks {want} but its extents cover {sum} block(s)"),
            );
        }
        if fork.logical_size > sum * self.bs {
            self.c.error(
                DiagCode::ForkSizeMismatch,
                loc(),
                format!(
                    "{what}: logical size {} exceeds its physical size {}",
                    fork.logical_size,
                    sum * self.bs
                ),
            );
        }
        Some(out)
    }

    fn check_overflow_leftovers(&mut self) {
        // The bad-block file owns its overflow records.
        if let Some(recs) = self.overflow.get(&(0, CNID_BAD_BLOCKS)).cloned() {
            self.overflow_used.insert((0, CNID_BAD_BLOCKS));
            for (_, exts) in recs {
                for e in exts {
                    if e.block_count == 0 {
                        break;
                    }
                    self.claim(
                        u64::from(e.start_block),
                        u64::from(e.block_count),
                        CNID_BAD_BLOCKS,
                        "bad-block file",
                    );
                }
            }
        }
        if self.incomplete {
            return;
        }
        let mut orphans: Vec<(u8, u32)> = self
            .overflow
            .keys()
            .filter(|k| !self.overflow_used.contains(k))
            .copied()
            .collect();
        orphans.sort_unstable();
        for (ft, id) in orphans {
            let n = self.overflow[&(ft, id)].len();
            self.c.error(
                DiagCode::OrphanRecord,
                Location::structure("extents-overflow").object(u64::from(id)),
                format!(
                    "{n} extents-overflow record(s) for the {} fork of CNID {id}, \
                     which has no fork needing them",
                    if ft == 0xFF { "resource" } else { "data" }
                ),
            );
        }
    }

    fn check_bitmap(&mut self, fork: &ForkData, extents: Vec<ExtentDescriptor>) -> Result<()> {
        let need = self.total.div_ceil(8);
        let phys: u64 = extents
            .iter()
            .map(|e| u64::from(e.block_count))
            .sum::<u64>()
            * self.bs;
        if phys < need || fork.logical_size < need {
            self.c.error(
                DiagCode::BitmapInvalid,
                Location::structure("allocation-bitmap"),
                format!(
                    "allocation file holds {} bytes ({} physical), the volume needs {need}",
                    fork.logical_size, phys
                ),
            );
            return Ok(());
        }
        let reader = ForkReader {
            base_offset: 0,
            block_size: self.bs as u32,
            extents,
            logical_size: fork.logical_size,
        };
        const CHUNK: u64 = 1 << 20;
        let mut free = 0u64;
        let mut leaked: Vec<u64> = Vec::new();
        let mut missing: Vec<u64> = Vec::new();
        let mut leaked_total = 0u64;
        let mut missing_total = 0u64;
        let mut reserved_free: Vec<u64> = Vec::new();
        // Coalesce into runs as we go; keep at most a bounded number of
        // individual block numbers per kind (the rest are only counted).
        const KEEP: usize = 1 << 16;
        let mut pos = 0u64;
        let mut buf = vec![0u8; CHUNK as usize];
        while pos < need {
            let n = (need - pos).min(CHUNK) as usize;
            if let Err(e) = reader.read(self.dev, pos, &mut buf[..n]) {
                self.c.error(
                    DiagCode::BitmapInvalid,
                    Location::structure("allocation-bitmap").at_byte(pos),
                    format!("allocation bitmap unreadable: {e}"),
                );
                return Ok(());
            }
            for (i, &disk) in buf[..n].iter().enumerate() {
                let byte_idx = pos + i as u64;
                let base = byte_idx * 8;
                let valid = (self.total - base).min(8) as u32;
                let mask: u8 = if valid == 8 { 0xFF } else { !(0xFFu8 >> valid) };
                let d = disk & mask;
                free += u64::from(valid - d.count_ones());
                let Some(map) = self.claimed.as_ref() else {
                    continue;
                };
                let c = map[byte_idx as usize] & mask;
                if c == d {
                    continue;
                }
                for bit in 0..valid {
                    let m = 0x80u8 >> bit;
                    let blk = base + u64::from(bit);
                    match (d & m != 0, c & m != 0) {
                        (true, false) => {
                            leaked_total += 1;
                            if leaked.len() < KEEP {
                                leaked.push(blk);
                            }
                        }
                        (false, true) => {
                            if self.reserved.iter().any(|&(s, n)| blk >= s && blk < s + n) {
                                reserved_free.push(blk);
                            } else {
                                missing_total += 1;
                                if missing.len() < KEEP {
                                    missing.push(blk);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            pos += n as u64;
        }
        self.c.report.stats.free_blocks = free;
        let vh_free = u64::from(be32(&self.vh, 48));
        if vh_free != free {
            self.c.error(
                DiagCode::FreeCountMismatch,
                Location::structure("volume-header").at_byte(1024 + 48),
                format!("freeBlocks is {vh_free} but the bitmap has {free} free block(s)"),
            );
        }
        if self.claimed.is_none() {
            return Ok(());
        }
        for (s, n) in crate::fs::verify::runs_of(reserved_free.into_iter()) {
            self.c.error(
                DiagCode::ReservedBlockFree,
                Location::structure("allocation-bitmap").blocks(s, n),
                format!("reserved block(s) {s}+{n} (volume headers) are marked free"),
            );
        }
        for (s, n) in crate::fs::verify::runs_of(missing.into_iter()) {
            self.c.error(
                DiagCode::BitmapMissingAllocation,
                Location::structure("allocation-bitmap").blocks(s, n),
                format!("blocks {s}+{n} are in use but marked free"),
            );
        }
        if missing_total > KEEP as u64 {
            self.c.error(
                DiagCode::BitmapMissingAllocation,
                Location::structure("allocation-bitmap"),
                format!("{missing_total} in-use block(s) marked free in all"),
            );
        }
        // Leaked blocks are only meaningful once every owner was seen.
        if !self.incomplete {
            for (s, n) in crate::fs::verify::runs_of(leaked.into_iter()) {
                self.c.error(
                    DiagCode::BitmapLeakedBlocks,
                    Location::structure("allocation-bitmap").blocks(s, n),
                    format!("blocks {s}+{n} are marked in use but no file owns them"),
                );
            }
            if leaked_total > KEEP as u64 {
                self.c.error(
                    DiagCode::BitmapLeakedBlocks,
                    Location::structure("allocation-bitmap"),
                    format!("{leaked_total} leaked block(s) in all"),
                );
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // B-trees
    // ------------------------------------------------------------------

    fn decode_key(&self, tree: Tree, rec: &[u8]) -> std::result::Result<(Key, usize), String> {
        let r = match tree {
            Tree::Catalog => CatalogKey::decode(rec).map(|k| {
                let l = k.encoded_len;
                (Key::Cat(k), l)
            }),
            Tree::Extents => ExtentKey::decode(rec).map(|k| (Key::Ext(k), k.encoded_len())),
            Tree::Attributes => AttrKey::decode(rec).map(|k| {
                let l = k.encoded_len;
                (Key::Attr(k), l)
            }),
        };
        let (k, len) = r.map_err(|e| e.to_string())?;
        if len > rec.len() {
            return Err(format!(
                "key of {len} bytes overruns its {}-byte record",
                rec.len()
            ));
        }
        Ok((k, len))
    }

    fn cmp(&self, a: &Key, b: &Key) -> Ordering {
        match (a, b) {
            (Key::Cat(x), Key::Cat(y)) => x.compare(y, self.case_sensitive),
            (Key::Ext(x), Key::Ext(y)) => x.order(y),
            (Key::Attr(x), Key::Attr(y)) => x.compare(y, true),
            _ => Ordering::Equal,
        }
    }

    /// Walk one B-tree level by level, checking its structure, and hand
    /// every leaf record to [`Self::leaf`].
    fn walk_tree(
        &mut self,
        tree: Tree,
        fork: &ForkData,
        extents: Vec<ExtentDescriptor>,
    ) -> Result<()> {
        let s = tree.name();
        let reader = ForkReader {
            base_offset: 0,
            block_size: self.bs as u32,
            extents,
            logical_size: fork.logical_size,
        };
        let phys = u64::from(fork.total_blocks) * self.bs;
        if phys < 512 {
            self.c.error(
                DiagCode::BTreeHeaderInvalid,
                Location::structure(s),
                "B-tree file is smaller than one node",
            );
            return Ok(());
        }
        // Header node: read the minimum node size first to learn the real one.
        let mut probe = [0u8; 512];
        if let Err(e) = reader.read(self.dev, 0, &mut probe) {
            self.c.error(
                DiagCode::BTreeHeaderInvalid,
                Location::structure(s).node(0, None),
                format!("header node unreadable: {e}"),
            );
            return Ok(());
        }
        let desc = NodeDescriptor::decode(&probe)?;
        if desc.kind != KIND_HEADER {
            self.c.error(
                DiagCode::BTreeHeaderInvalid,
                Location::structure(s).node(0, None),
                format!(
                    "node 0 has kind {}, expected the header node (1)",
                    desc.kind
                ),
            );
            return Ok(());
        }
        let hdr = match BTreeHeader::decode(&probe[NODE_DESCRIPTOR_SIZE..]) {
            Ok(h) => h,
            Err(e) => {
                self.c.error(
                    DiagCode::BTreeHeaderInvalid,
                    Location::structure(s).node(0, Some(0)),
                    e.to_string(),
                );
                return Ok(());
            }
        };
        let node_size = u64::from(hdr.node_size);
        if !(512..=32768).contains(&node_size) {
            self.c.error(
                DiagCode::BTreeHeaderInvalid,
                Location::structure(s).node(0, Some(0)),
                format!("nodeSize {node_size} is outside 512..=32768"),
            );
            return Ok(());
        }
        let total_nodes = u64::from(hdr.total_nodes);
        if total_nodes == 0 || total_nodes * node_size > phys {
            self.c.error(
                DiagCode::BTreeHeaderInvalid,
                Location::structure(s).node(0, Some(0)),
                format!(
                    "totalNodes {total_nodes} x nodeSize {node_size} does not fit the \
                     {phys}-byte file"
                ),
            );
            return Ok(());
        }
        if total_nodes * node_size > fork.logical_size {
            self.c.error(
                DiagCode::ForkSizeMismatch,
                Location::structure(s),
                format!(
                    "totalNodes {total_nodes} x nodeSize {node_size} exceeds the file's \
                     logical size {}",
                    fork.logical_size
                ),
            );
        }
        if hdr.free_nodes > hdr.total_nodes {
            self.c.error(
                DiagCode::BTreeHeaderInvalid,
                Location::structure(s).node(0, Some(0)),
                format!(
                    "freeNodes {} exceeds totalNodes {}",
                    hdr.free_nodes, hdr.total_nodes
                ),
            );
        }
        if hdr.max_key_length != tree.max_key_length() {
            self.c.warn(
                DiagCode::BTreeHeaderInvalid,
                Location::structure(s).node(0, Some(0)),
                format!(
                    "maxKeyLength {} (expected {})",
                    hdr.max_key_length,
                    tree.max_key_length()
                ),
            );
        }
        if tree == Tree::Catalog {
            let kct = hdr.key_compare_type;
            if self.hfsx {
                if kct != KEY_COMPARE_BINARY && kct != 0xCF {
                    self.c.error(
                        DiagCode::BTreeHeaderInvalid,
                        Location::structure(s).node(0, Some(0)),
                        format!("HFSX catalog keyCompareType {kct:#04x} is neither 0xCF nor 0xBC"),
                    );
                }
                self.case_sensitive = kct == KEY_COMPARE_BINARY;
            } else {
                self.case_sensitive = false;
            }
        }

        let node_size_u32 = node_size as u32;
        let read = |dev: &mut dyn BlockDevice, n: u32| -> Result<Vec<u8>> {
            let mut buf = vec![0u8; node_size as usize];
            reader.read(dev, u64::from(n) * node_size, &mut buf)?;
            Ok(buf)
        };

        // Header node in full: descriptor + three records.
        let node0 = match read(self.dev, 0) {
            Ok(n) => n,
            Err(e) => {
                self.c.error(
                    DiagCode::BTreeHeaderInvalid,
                    Location::structure(s).node(0, None),
                    format!("header node unreadable: {e}"),
                );
                return Ok(());
            }
        };
        let _ = node_size_u32;
        let mut in_map = vec![0u8; total_nodes.div_ceil(8) as usize];
        let mut visited = vec![0u8; total_nodes.div_ceil(8) as usize];
        let set = |v: &mut Vec<u8>, n: u64| v[(n / 8) as usize] |= 0x80 >> (n % 8);
        let get = |v: &Vec<u8>, n: u64| v[(n / 8) as usize] & (0x80 >> (n % 8)) != 0;
        set(&mut visited, 0);

        // Node map: the header node's third record, continued in map nodes.
        let mut map_bits: u64 = 0;
        let mut map_ok = true;
        {
            let d0 = NodeDescriptor::decode(&node0)?;
            match record_offsets(&node0, d0.num_records) {
                Ok(offs) if d0.num_records == 3 => {
                    let rec0 = &node0[offs[0] as usize..offs[1] as usize];
                    if rec0.len() < HEADER_REC_SIZE {
                        self.c.error(
                            DiagCode::BTreeHeaderInvalid,
                            Location::structure(s).node(0, Some(0)),
                            "header record shorter than 106 bytes",
                        );
                    }
                    let map = &node0[offs[2] as usize..offs[3] as usize];
                    for (i, &b) in map.iter().enumerate() {
                        for bit in 0..8u64 {
                            let n = i as u64 * 8 + bit;
                            if n < total_nodes && b & (0x80 >> bit) != 0 {
                                set(&mut in_map, n);
                            }
                        }
                    }
                    map_bits += map.len() as u64 * 8;
                }
                Ok(_) => {
                    self.c.error(
                        DiagCode::BTreeHeaderInvalid,
                        Location::structure(s).node(0, None),
                        format!("header node has {} records, expected 3", d0.num_records),
                    );
                    map_ok = false;
                }
                Err(e) => {
                    self.c.error(
                        DiagCode::BTreeRecordOffsets,
                        Location::structure(s).node(0, None),
                        e.to_string(),
                    );
                    map_ok = false;
                }
            }
            let mut next = d0.f_link;
            while next != 0 && map_ok {
                let n = u64::from(next);
                if n >= total_nodes || get(&visited, n) {
                    self.c.error(
                        DiagCode::BTreeNodeMap,
                        Location::structure(s).node(next, None),
                        "map-node chain points outside the tree or loops",
                    );
                    map_ok = false;
                    break;
                }
                if !self.c.take_node() {
                    self.incomplete = true;
                    return Ok(());
                }
                set(&mut visited, n);
                let node = match read(self.dev, next) {
                    Ok(b) => b,
                    Err(e) => {
                        self.c.error(
                            DiagCode::BTreeNodeInvalid,
                            Location::structure(s).node(next, None),
                            format!("map node unreadable: {e}"),
                        );
                        map_ok = false;
                        break;
                    }
                };
                let d = NodeDescriptor::decode(&node)?;
                if d.kind != KIND_MAP {
                    self.c.error(
                        DiagCode::BTreeNodeInvalid,
                        Location::structure(s).node(next, None),
                        format!("map-chain node has kind {}, expected 2", d.kind),
                    );
                    map_ok = false;
                    break;
                }
                match record_offsets(&node, d.num_records) {
                    Ok(offs) if d.num_records >= 1 => {
                        let map = &node[offs[0] as usize..offs[1] as usize];
                        for (i, &b) in map.iter().enumerate() {
                            for bit in 0..8u64 {
                                let nn = map_bits + i as u64 * 8 + bit;
                                if nn < total_nodes && b & (0x80 >> bit) != 0 {
                                    set(&mut in_map, nn);
                                }
                            }
                        }
                        map_bits += map.len() as u64 * 8;
                    }
                    _ => {
                        self.c.error(
                            DiagCode::BTreeRecordOffsets,
                            Location::structure(s).node(next, None),
                            "map node record table is malformed",
                        );
                        map_ok = false;
                        break;
                    }
                }
                next = d.f_link;
            }
            if map_ok && map_bits < total_nodes {
                self.c.error(
                    DiagCode::BTreeNodeMap,
                    Location::structure(s),
                    format!("node map covers {map_bits} nodes, the tree has {total_nodes}"),
                );
            }
        }

        // Empty tree.
        let depth = u32::from(hdr.tree_depth);
        if hdr.root_node == 0 {
            if depth != 0 || hdr.leaf_records != 0 || hdr.first_leaf_node != 0 {
                self.c.error(
                    DiagCode::BTreeHeaderMismatch,
                    Location::structure(s).node(0, Some(0)),
                    "rootNode is 0 but the header claims depth or records",
                );
            }
        } else if u64::from(hdr.root_node) >= total_nodes || depth == 0 {
            self.c.error(
                DiagCode::BTreeHeaderInvalid,
                Location::structure(s).node(0, Some(0)),
                format!(
                    "rootNode {} / treeDepth {depth} invalid for {total_nodes} nodes",
                    hdr.root_node
                ),
            );
            return Ok(());
        } else if depth > 16 {
            self.c.error(
                DiagCode::BTreeHeaderInvalid,
                Location::structure(s).node(0, Some(0)),
                format!("treeDepth {depth} is implausible"),
            );
            return Ok(());
        }

        let variable_index = hdr.attributes & BT_VARIABLE_INDEX_KEYS != 0;
        let mut level: Vec<(u32, Option<Key>)> = if hdr.root_node != 0 {
            vec![(hdr.root_node, None)]
        } else {
            Vec::new()
        };
        let mut height = depth;
        let mut leaf_count: u64 = 0;
        let mut first_leaf: Option<u32> = None;
        let mut last_leaf: u32 = 0;
        let mut truncated = false;
        'levels: while !level.is_empty() {
            if height == 0 {
                self.c.error(
                    DiagCode::BTreeHeaderMismatch,
                    Location::structure(s),
                    format!("index nodes below the declared depth {depth}"),
                );
                break;
            }
            let want_kind = if height == 1 { KIND_LEAF } else { KIND_INDEX };
            let mut next_level: Vec<(u32, Option<Key>)> = Vec::new();
            let mut prev: Option<(u32, u32)> = None; // (node, its fLink)
            let mut prev_key: Option<Key> = None;
            for (n, expect) in std::mem::take(&mut level) {
                let nn = u64::from(n);
                if n == 0 || nn >= total_nodes {
                    self.c.error(
                        DiagCode::BTreeNodeInvalid,
                        Location::structure(s).node(n, None),
                        format!("child pointer {n} is outside 1..{total_nodes}"),
                    );
                    continue;
                }
                if get(&visited, nn) {
                    self.c.error(
                        DiagCode::BTreeNodeInvalid,
                        Location::structure(s).node(n, None),
                        "node is reachable more than once (cycle or shared child)",
                    );
                    continue;
                }
                if !self.c.take_node() {
                    truncated = true;
                    break 'levels;
                }
                set(&mut visited, nn);
                let node = match read(self.dev, n) {
                    Ok(b) => b,
                    Err(e) => {
                        self.c.error(
                            DiagCode::BTreeNodeInvalid,
                            Location::structure(s).node(n, None),
                            format!("node unreadable: {e}"),
                        );
                        continue;
                    }
                };
                let d = NodeDescriptor::decode(&node)?;
                // Sibling links.
                let want_blink = prev.map_or(0, |p| p.0);
                if d.b_link != want_blink {
                    self.c.error(
                        DiagCode::BTreeSiblingLink,
                        Location::structure(s).node(n, None),
                        format!("bLink is {}, expected {want_blink}", d.b_link),
                    );
                }
                if let Some((pn, pf)) = prev
                    && pf != n
                {
                    self.c.error(
                        DiagCode::BTreeSiblingLink,
                        Location::structure(s).node(pn, None),
                        format!("fLink is {pf}, expected {n}"),
                    );
                }
                prev = Some((n, d.f_link));
                if d.kind != want_kind || u32::from(d.height) != height {
                    self.c.error(
                        DiagCode::BTreeNodeInvalid,
                        Location::structure(s).node(n, None),
                        format!(
                            "node kind {} height {}, expected kind {want_kind} height {height}",
                            d.kind, d.height
                        ),
                    );
                    continue;
                }
                if d.num_records == 0 {
                    self.c.error(
                        DiagCode::BTreeNodeInvalid,
                        Location::structure(s).node(n, None),
                        "node in the tree holds no records",
                    );
                    continue;
                }
                let offs = match record_offsets(&node, d.num_records) {
                    Ok(o) => o,
                    Err(e) => {
                        self.c.error(
                            DiagCode::BTreeRecordOffsets,
                            Location::structure(s).node(n, None),
                            e.to_string(),
                        );
                        continue;
                    }
                };
                if d.kind == KIND_LEAF {
                    first_leaf.get_or_insert(n);
                    last_leaf = n;
                }
                for i in 0..d.num_records as usize {
                    if !self.c.take_record() {
                        truncated = true;
                        break 'levels;
                    }
                    let rec = &node[offs[i] as usize..offs[i + 1] as usize];
                    let loc = || Location::structure(s).node(n, Some(i as u32));
                    if rec.len() >= 2 && be16(rec, 0) > hdr.max_key_length {
                        self.c.error(
                            DiagCode::BTreeKeyInvalid,
                            loc(),
                            format!(
                                "keyLength {} exceeds maxKeyLength {}",
                                be16(rec, 0),
                                hdr.max_key_length
                            ),
                        );
                        continue;
                    }
                    let (key, klen) = match self.decode_key(tree, rec) {
                        Ok(k) => k,
                        Err(e) => {
                            self.c.error(DiagCode::BTreeKeyInvalid, loc(), e);
                            continue;
                        }
                    };
                    if i == 0
                        && let Some(exp) = &expect
                        && self.cmp(exp, &key) != Ordering::Equal
                    {
                        self.c.error(
                            DiagCode::BTreeIndexKeyMismatch,
                            loc(),
                            "the parent index record's key differs from this node's first key",
                        );
                    }
                    if let Some(pk) = &prev_key
                        && self.cmp(pk, &key) != Ordering::Less
                    {
                        self.c.error(
                            DiagCode::BTreeKeyOrder,
                            loc(),
                            "key is not greater than the previous key",
                        );
                    }
                    if d.kind == KIND_INDEX {
                        let ptr_off = if variable_index {
                            klen
                        } else {
                            2 + usize::from(hdr.max_key_length)
                        };
                        let ptr_off = ptr_off + (ptr_off & 1);
                        if ptr_off + 4 > rec.len() {
                            self.c.error(
                                DiagCode::BTreeKeyInvalid,
                                loc(),
                                "index record has no child pointer",
                            );
                            continue;
                        }
                        let child = be32(rec, ptr_off);
                        next_level.push((child, Some(key.clone())));
                    } else {
                        leaf_count += 1;
                        let body_off = klen + (klen & 1);
                        let body = &rec[body_off.min(rec.len())..];
                        self.leaf(tree, &key, body, n, i as u32);
                    }
                    prev_key = Some(key);
                }
            }
            if let Some((pn, pf)) = prev
                && pf != 0
            {
                self.c.error(
                    DiagCode::BTreeSiblingLink,
                    Location::structure(s).node(pn, None),
                    format!("last node of its level has fLink {pf}, expected 0"),
                );
            }
            level = next_level;
            height -= 1;
        }
        if truncated {
            self.incomplete = true;
            return Ok(());
        }
        if hdr.root_node != 0 && height != 0 {
            self.c.error(
                DiagCode::BTreeHeaderMismatch,
                Location::structure(s).node(0, Some(0)),
                format!(
                    "treeDepth {depth} but the leaves sit at depth {}",
                    depth - height
                ),
            );
        }
        if u64::from(hdr.leaf_records) != leaf_count {
            self.c.error(
                DiagCode::BTreeHeaderMismatch,
                Location::structure(s).node(0, Some(0)),
                format!(
                    "leafRecords {} but the leaves hold {leaf_count}",
                    hdr.leaf_records
                ),
            );
        }
        if hdr.root_node != 0
            && (Some(hdr.first_leaf_node) != first_leaf || hdr.last_leaf_node != last_leaf)
        {
            self.c.error(
                DiagCode::BTreeHeaderMismatch,
                Location::structure(s).node(0, Some(0)),
                format!(
                    "firstLeafNode/lastLeafNode {}/{} but the leaf chain runs {}/{}",
                    hdr.first_leaf_node,
                    hdr.last_leaf_node,
                    first_leaf.unwrap_or(0),
                    last_leaf
                ),
            );
        }
        if map_ok {
            let mut unmarked: Vec<u64> = Vec::new();
            let mut unreachable: Vec<u64> = Vec::new();
            let mut used = 0u64;
            for n in 0..total_nodes {
                let m = get(&in_map, n);
                let v = get(&visited, n);
                used += u64::from(m);
                if v && !m {
                    unmarked.push(n);
                } else if m && !v {
                    unreachable.push(n);
                }
            }
            for (a, k) in crate::fs::verify::runs_of(unmarked.into_iter()) {
                self.c.error(
                    DiagCode::BTreeNodeMap,
                    Location::structure(s).node(a as u32, None),
                    format!("{k} node(s) from {a} are in use but marked free in the node map"),
                );
            }
            for (a, k) in crate::fs::verify::runs_of(unreachable.into_iter()) {
                self.c.error(
                    DiagCode::BTreeNodeMap,
                    Location::structure(s).node(a as u32, None),
                    format!("{k} node(s) from {a} are marked in use but unreachable"),
                );
            }
            let want_used = total_nodes - u64::from(hdr.free_nodes.min(hdr.total_nodes));
            if used != want_used {
                self.c.error(
                    DiagCode::BTreeHeaderMismatch,
                    Location::structure(s).node(0, Some(0)),
                    format!(
                        "freeNodes {} but the node map marks {} of {total_nodes} free",
                        hdr.free_nodes,
                        total_nodes - used
                    ),
                );
            }
        }
        Ok(())
    }

    fn leaf(&mut self, tree: Tree, key: &Key, body: &[u8], node: u32, rec: u32) {
        match (tree, key) {
            (Tree::Extents, Key::Ext(k)) => self.extents_leaf(k, body, node, rec),
            (Tree::Catalog, Key::Cat(k)) => self.catalog_leaf(k, body, node, rec),
            (Tree::Attributes, Key::Attr(k)) => self.attr_leaf(k, body, node, rec),
            _ => {}
        }
    }

    fn extents_leaf(&mut self, k: &ExtentKey, body: &[u8], node: u32, rec: u32) {
        let loc = || {
            Location::structure("extents-overflow")
                .node(node, Some(rec))
                .object(u64::from(k.file_id))
        };
        if k.fork_type != 0 && k.fork_type != 0xFF {
            self.c.error(
                DiagCode::RecordInvalid,
                loc(),
                format!(
                    "fork type {:#04x} is neither data nor resource",
                    k.fork_type
                ),
            );
            return;
        }
        match decode_extent_record(body) {
            Ok(exts) => self
                .overflow
                .entry((k.fork_type, k.file_id))
                .or_default()
                .push((k.start_block, exts)),
            Err(e) => self.c.error(DiagCode::RecordInvalid, loc(), e.to_string()),
        }
    }

    fn catalog_leaf(&mut self, k: &CatalogKey, body: &[u8], node: u32, rec: u32) {
        let loc = |id: u32| {
            Location::structure("catalog")
                .node(node, Some(rec))
                .object(u64::from(id))
        };
        let parsed = match CatalogRecord::decode(body) {
            Ok(r) => r,
            Err(e) => {
                self.c.error(DiagCode::RecordInvalid, loc(0), e.to_string());
                return;
            }
        };
        let rtype = i16::from_be_bytes([body[0], body[1]]);
        let next_id = be32(&self.vh, 64);
        let reused = be32(&self.vh, 4) & ATTR_CNIDS_REUSED != 0;
        let check_id = |c: &mut Collector, id: u32| {
            if id != ROOT_FOLDER_ID && id < FIRST_USER_CNID {
                c.error(
                    DiagCode::IdOutOfRange,
                    loc(id),
                    format!("CNID {id} lies in the reserved range"),
                );
            } else if !reused && id >= next_id {
                c.error(
                    DiagCode::IdOutOfRange,
                    loc(id),
                    format!("CNID {id} is not below nextCatalogID {next_id}"),
                );
            }
        };
        let nh = name_hash(&k.name.code_units);
        match parsed {
            CatalogRecord::Folder(f) => {
                check_id(&mut self.c, f.folder_id);
                self.folders += 1;
                if k.parent_id == ROOT_FOLDER_ID && k.name.code_units == private_dir_name() {
                    self.private_dir = Some(f.folder_id);
                }
                self.add_rec(
                    f.folder_id,
                    RecInfo {
                        parent: k.parent_id,
                        name_hash: nh,
                        folder: true,
                        valence: f.valence,
                    },
                    loc(f.folder_id),
                );
            }
            CatalogRecord::File(f) => {
                check_id(&mut self.c, f.file_id);
                self.files += 1;
                self.add_rec(
                    f.file_id,
                    RecInfo {
                        parent: k.parent_id,
                        name_hash: nh,
                        folder: false,
                        valence: 0,
                    },
                    loc(f.file_id),
                );
                if f.is_hard_link() {
                    *self.link_refs.entry(f.bsd.special).or_default() += 1;
                }
                let name = String::from_utf16_lossy(&k.name.code_units);
                if let Some(num) = name.strip_prefix("iNode")
                    && let Ok(n) = num.parse::<u32>()
                {
                    self.inodes.push((k.parent_id, n, f.bsd.special, f.file_id));
                }
                for (fork, ft, what) in [
                    (f.data_fork, 0u8, "data fork"),
                    (f.resource_fork, 0xFFu8, "resource fork"),
                ] {
                    if fork.total_blocks == 0 && fork.logical_size == 0 {
                        continue;
                    }
                    if let Some(list) = self.fork_extents(&fork, f.file_id, ft, what) {
                        for e in list {
                            self.claim(
                                u64::from(e.start_block),
                                u64::from(e.block_count),
                                f.file_id,
                                what,
                            );
                        }
                    }
                }
            }
            CatalogRecord::Thread(t) => {
                let id = k.parent_id;
                if !k.name.code_units.is_empty() {
                    self.c.error(
                        DiagCode::RecordInvalid,
                        loc(id),
                        "thread record key carries a name",
                    );
                }
                let info = ThreadInfo {
                    parent: t.parent_id,
                    name_hash: name_hash(&t.name.code_units),
                    folder: rtype == REC_FOLDER_THREAD,
                };
                if self.threads.insert(id, info).is_some() {
                    self.c.error(
                        DiagCode::DuplicateId,
                        loc(id),
                        format!("second thread record for CNID {id}"),
                    );
                }
            }
        }
        let _ = (REC_FILE, REC_FOLDER, REC_FILE_THREAD);
    }

    fn add_rec(&mut self, id: u32, info: RecInfo, loc: Location) {
        *self.children.entry(info.parent).or_default() += 1;
        if self.recs.insert(id, info).is_some() {
            self.c.error(
                DiagCode::DuplicateId,
                loc,
                format!("CNID {id} is used by more than one catalog record"),
            );
        }
    }

    fn check_catalog_semantics(&mut self) {
        if self.incomplete {
            return;
        }
        let loc = |id: u32| Location::structure("catalog").object(u64::from(id));
        let mut ids: Vec<u32> = self.recs.keys().copied().collect();
        ids.sort_unstable();
        for &id in &ids {
            let r = self.recs[&id];
            match self.threads.get(&id) {
                None => self.c.error(
                    DiagCode::ThreadMissing,
                    loc(id),
                    format!(
                        "{} CNID {id} has no thread record",
                        if r.folder { "folder" } else { "file" }
                    ),
                ),
                Some(t) => {
                    if t.parent != r.parent || t.name_hash != r.name_hash {
                        self.c.error(
                            DiagCode::ThreadMismatch,
                            loc(id),
                            format!(
                                "thread record of CNID {id} names parent {} / a different \
                                 name than its record (parent {})",
                                t.parent, r.parent
                            ),
                        );
                    } else if t.folder != r.folder {
                        self.c.error(
                            DiagCode::ThreadMismatch,
                            loc(id),
                            format!("thread record type of CNID {id} does not match its record"),
                        );
                    }
                }
            }
            if r.folder {
                let have = self.children.get(&id).copied().unwrap_or(0);
                if have != r.valence {
                    self.c.error(
                        DiagCode::ValenceMismatch,
                        loc(id),
                        format!(
                            "folder CNID {id} has valence {} but {have} child record(s)",
                            r.valence
                        ),
                    );
                }
            }
            if id != ROOT_FOLDER_ID && !self.recs.get(&r.parent).is_some_and(|p| p.folder) {
                self.c.error(
                    DiagCode::OrphanRecord,
                    loc(id),
                    format!("CNID {id}'s parent {} is not a folder", r.parent),
                );
            }
        }
        let mut tids: Vec<u32> = self.threads.keys().copied().collect();
        tids.sort_unstable();
        for id in tids {
            if !self.recs.contains_key(&id) {
                self.c.error(
                    DiagCode::ThreadMissing,
                    loc(id),
                    format!("thread record for CNID {id}, which has no file or folder record"),
                );
            }
        }
        match self.recs.get(&ROOT_FOLDER_ID) {
            Some(r) if r.folder && r.parent == ROOT_PARENT_ID => {}
            _ => self.c.error(
                DiagCode::RootMissing,
                loc(ROOT_FOLDER_ID),
                "the root folder (CNID 2, parent 1) is missing",
            ),
        }
        let vh_files = u64::from(be32(&self.vh, 32));
        let vh_folders = u64::from(be32(&self.vh, 36));
        if vh_files != self.files {
            self.c.error(
                DiagCode::CountMismatch,
                Location::structure("volume-header").at_byte(1024 + 32),
                format!(
                    "fileCount is {vh_files} but the catalog holds {}",
                    self.files
                ),
            );
        }
        let folders_wo_root = self.folders.saturating_sub(1);
        if vh_folders != folders_wo_root {
            self.c.error(
                DiagCode::CountMismatch,
                Location::structure("volume-header").at_byte(1024 + 36),
                format!(
                    "folderCount is {vh_folders} but the catalog holds {folders_wo_root} \
                     (excluding the root)"
                ),
            );
        }
        // Hard links.
        if let Some(pd) = self.private_dir {
            let mut seen: HashSet<u32> = HashSet::new();
            for &(parent, n, count, cnid) in &self.inodes {
                if parent != pd {
                    continue;
                }
                seen.insert(n);
                let links = self.link_refs.get(&n).copied().unwrap_or(0);
                if links != count {
                    self.c.error(
                        DiagCode::LinkCountMismatch,
                        loc(cnid),
                        format!(
                            "indirect node iNode{n} has link count {count} but {links} link(s)"
                        ),
                    );
                }
            }
            let mut missing: Vec<u32> = self
                .link_refs
                .keys()
                .filter(|n| !seen.contains(n))
                .copied()
                .collect();
            missing.sort_unstable();
            for n in missing {
                self.c.error(
                    DiagCode::LinkCountMismatch,
                    loc(n),
                    format!("hard link(s) to iNode{n}, which does not exist"),
                );
            }
        } else if !self.link_refs.is_empty() {
            self.c.error(
                DiagCode::LinkCountMismatch,
                loc(0),
                "hard links exist but the volume has no private data directory",
            );
        }
    }

    fn attr_leaf(&mut self, k: &AttrKey, body: &[u8], node: u32, rec: u32) {
        let loc = || {
            Location::structure("attributes")
                .node(node, Some(rec))
                .object(u64::from(k.file_id))
        };
        if !self.incomplete && !self.recs.contains_key(&k.file_id) {
            self.c.error(
                DiagCode::OrphanRecord,
                loc(),
                format!(
                    "attribute {:?} belongs to CNID {}, which does not exist",
                    String::from_utf16_lossy(&k.name.code_units),
                    k.file_id
                ),
            );
        }
        if body.len() < 4 {
            self.c
                .error(DiagCode::RecordInvalid, loc(), "attribute record too short");
            return;
        }
        let rtype = be32(body, 0);
        if rtype != ATTR_EXTENTS {
            self.close_attr_fork();
        }
        match rtype {
            ATTR_INLINE => {
                if body.len() < 16 || (be32(body, 12) as usize) > body.len() - 16 {
                    self.c.error(
                        DiagCode::RecordInvalid,
                        loc(),
                        "inline attribute size exceeds its record",
                    );
                }
            }
            ATTR_FORK => {
                if body.len() < 88 {
                    self.c.error(
                        DiagCode::RecordInvalid,
                        loc(),
                        "short attribute fork record",
                    );
                    return;
                }
                let mut tmp = [0u8; FORK_DATA_SIZE];
                tmp.copy_from_slice(&body[8..88]);
                let fork = ForkData::decode(&tmp);
                let mut covered = 0u64;
                let mut ended = false;
                for e in fork.extents {
                    if e.block_count == 0 {
                        ended = true;
                        continue;
                    }
                    if ended || !self.c.take_extent() {
                        if ended {
                            self.c.error(
                                DiagCode::ForkExtentsInvalid,
                                loc(),
                                "a non-empty extent follows an empty one",
                            );
                        } else {
                            self.incomplete = true;
                        }
                        break;
                    }
                    covered += u64::from(e.block_count);
                    self.claim(
                        u64::from(e.start_block),
                        u64::from(e.block_count),
                        k.file_id,
                        "attribute fork",
                    );
                }
                self.open_attr = Some(OpenAttrFork {
                    file_id: k.file_id,
                    name: k.name.code_units.clone(),
                    total_blocks: u64::from(fork.total_blocks),
                    covered,
                    logical_size: fork.logical_size,
                });
            }
            ATTR_EXTENTS => {
                let ok = matches!(&self.open_attr, Some(o)
                    if o.file_id == k.file_id && o.name == k.name.code_units
                        && o.covered == u64::from(k.start_block));
                if !ok || body.len() < 72 {
                    self.c.error(
                        DiagCode::ForkExtentsInvalid,
                        loc(),
                        "attribute extents record does not continue a preceding fork record",
                    );
                    return;
                }
                let mut add = 0u64;
                for i in 0..8 {
                    let s = be32(body, 8 + i * 8);
                    let n = be32(body, 12 + i * 8);
                    if n == 0 {
                        break;
                    }
                    if !self.c.take_extent() {
                        self.incomplete = true;
                        break;
                    }
                    add += u64::from(n);
                    self.claim(u64::from(s), u64::from(n), k.file_id, "attribute fork");
                }
                if let Some(o) = self.open_attr.as_mut() {
                    o.covered += add;
                }
            }
            other => self.c.error(
                DiagCode::RecordInvalid,
                loc(),
                format!("unknown attribute record type {other:#x}"),
            ),
        }
    }

    fn close_attr_fork(&mut self) {
        if let Some(o) = self.open_attr.take() {
            let loc = Location::structure("attributes").object(u64::from(o.file_id));
            if o.covered != o.total_blocks {
                self.c.error(
                    DiagCode::ForkSizeMismatch,
                    loc,
                    format!(
                        "attribute {:?} fork has totalBlocks {} but its extents cover {}",
                        String::from_utf16_lossy(&o.name),
                        o.total_blocks,
                        o.covered
                    ),
                );
            } else if o.logical_size > o.covered * self.bs {
                self.c.error(
                    DiagCode::ForkSizeMismatch,
                    loc,
                    format!(
                        "attribute {:?} fork logical size {} exceeds its physical size",
                        String::from_utf16_lossy(&o.name),
                        o.logical_size
                    ),
                );
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::block::MemoryBackend;
    use crate::fs::hfs_plus::{FormatOpts, HfsPlus};
    use crate::fs::verify::Severity;

    pub(crate) fn sample(case_sensitive: bool) -> MemoryBackend {
        let mut dev = MemoryBackend::new(8 * 1024 * 1024);
        let opts = FormatOpts {
            case_sensitive,
            ..FormatOpts::default()
        };
        let mut fs = HfsPlus::format(&mut dev, &opts).unwrap();
        fs.create_dir(&mut dev, "/d", 0o755, 0, 0, 0).unwrap();
        for i in 0..40usize {
            let body = vec![i as u8; 1000 + i * 300];
            fs.create_file(
                &mut dev,
                &format!("/d/file{i}"),
                &mut std::io::Cursor::new(&body),
                body.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
        }
        fs.create_hardlink(&mut dev, "/d/file1", "/d/link1")
            .unwrap();
        fs.set_xattr(&mut dev, "/d/file2", "user.big", &vec![7u8; 9000])
            .unwrap();
        fs.set_xattr(&mut dev, "/d/file3", "user.small", b"hi")
            .unwrap();
        let rsrc = vec![3u8; 5000];
        fs.write_resource_fork(&mut dev, "/d/file4", &mut std::io::Cursor::new(&rsrc), 5000)
            .unwrap();
        fs.flush(&mut dev).unwrap();
        dev
    }

    fn report(dev: &mut MemoryBackend) -> VerifyReport {
        verify(dev, &VerifyOpts::default()).unwrap()
    }

    fn vh_u32(dev: &mut MemoryBackend, off: u64) -> u32 {
        let mut b = [0u8; 4];
        dev.read_at(1024 + off, &mut b).unwrap();
        u32::from_be_bytes(b)
    }

    #[test]
    fn fresh_volume_verifies_clean() {
        for cs in [false, true] {
            let mut dev = sample(cs);
            let r = report(&mut dev);
            assert!(r.is_clean(), "{:#?}", r.diagnostics);
            assert_eq!(r.fs, if cs { "hfsx" } else { "hfs+" });
            assert!(r.stats.files >= 40, "{:?}", r.stats);
            assert!(r.stats.nodes > 0);
        }
    }

    #[test]
    fn free_count_corruption_is_flagged() {
        let mut dev = sample(false);
        let free = vh_u32(&mut dev, 48);
        dev.write_at(1024 + 48, &(free - 3).to_be_bytes()).unwrap();
        let r = report(&mut dev);
        assert!(r.has(DiagCode::FreeCountMismatch), "{:#?}", r.diagnostics);
    }

    #[test]
    fn cleared_bitmap_bit_is_flagged() {
        let mut dev = sample(false);
        // Clear the bit of the catalog's first block.
        let mut vh = [0u8; 512];
        dev.read_at(1024, &mut vh).unwrap();
        let alloc = fork_at(&vh, FORK_ALLOCATION);
        let cat = fork_at(&vh, FORK_CATALOG);
        let bs = u64::from(be32(&vh, 40));
        let blk = u64::from(cat.extents[0].start_block);
        let off = u64::from(alloc.extents[0].start_block) * bs + blk / 8;
        let mut b = [0u8; 1];
        dev.read_at(off, &mut b).unwrap();
        b[0] &= !(0x80 >> (blk % 8));
        dev.write_at(off, &b).unwrap();
        let r = report(&mut dev);
        assert!(
            r.has(DiagCode::BitmapMissingAllocation),
            "{:#?}",
            r.diagnostics
        );
        assert!(r.has(DiagCode::FreeCountMismatch));
    }

    #[test]
    fn leaked_block_is_flagged() {
        let mut dev = sample(false);
        let mut vh = [0u8; 512];
        dev.read_at(1024, &mut vh).unwrap();
        let alloc = fork_at(&vh, FORK_ALLOCATION);
        let bs = u64::from(be32(&vh, 40));
        let total = u64::from(be32(&vh, 44));
        let blk = total - 10; // free on a fresh volume
        let off = u64::from(alloc.extents[0].start_block) * bs + blk / 8;
        let mut b = [0u8; 1];
        dev.read_at(off, &mut b).unwrap();
        b[0] |= 0x80 >> (blk % 8);
        dev.write_at(off, &b).unwrap();
        let free = vh_u32(&mut dev, 48);
        dev.write_at(1024 + 48, &(free - 1).to_be_bytes()).unwrap();
        let r = report(&mut dev);
        assert!(r.has(DiagCode::BitmapLeakedBlocks), "{:#?}", r.diagnostics);
        assert!(!r.has(DiagCode::FreeCountMismatch));
    }

    #[test]
    fn broken_catalog_node_is_flagged() {
        let mut dev = sample(false);
        let mut vh = [0u8; 512];
        dev.read_at(1024, &mut vh).unwrap();
        let cat = fork_at(&vh, FORK_CATALOG);
        let bs = u64::from(be32(&vh, 40));
        let base = u64::from(cat.extents[0].start_block) * bs;
        // Read the header to find the root node, then swap two record
        // offsets of the first leaf.
        let mut hdr = [0u8; 512];
        dev.read_at(base, &mut hdr).unwrap();
        let h = BTreeHeader::decode(&hdr[14..]).unwrap();
        let leaf = u64::from(h.first_leaf_node) * u64::from(h.node_size);
        let mut node = vec![0u8; h.node_size as usize];
        dev.read_at(base + leaf, &mut node).unwrap();
        // Corrupt the fLink of the first leaf.
        node[0..4].copy_from_slice(&0xFFFF_FFF0u32.to_be_bytes());
        dev.write_at(base + leaf, &node).unwrap();
        let r = report(&mut dev);
        assert!(!r.is_clean());
        assert!(r.has(DiagCode::BTreeSiblingLink), "{:#?}", r.diagnostics);
    }

    #[test]
    fn alternate_header_damage_is_flagged() {
        let mut dev = sample(false);
        let end = dev.total_size();
        dev.write_at(end - 1024, &[0u8; 512]).unwrap();
        let r = report(&mut dev);
        assert!(
            r.has(DiagCode::AlternateHeaderMissing),
            "{:#?}",
            r.diagnostics
        );
    }

    #[test]
    fn garbage_is_reported_not_panicked() {
        let mut dev = MemoryBackend::new(1 << 20);
        let r = report(&mut dev);
        assert!(r.has(DiagCode::HeaderUnreadable));
        // A valid-looking header over garbage must not panic either.
        let mut dev = sample(false);
        let mut vh = [0u8; 512];
        dev.read_at(1024, &mut vh).unwrap();
        let cat = fork_at(&vh, FORK_CATALOG);
        let bs = u64::from(be32(&vh, 40));
        let base = u64::from(cat.extents[0].start_block) * bs;
        let mut x: u32 = 12345;
        let mut junk = vec![0u8; 64 * 1024];
        for b in junk.iter_mut().skip(256) {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            *b = (x >> 16) as u8;
        }
        dev.write_at(base, &junk).unwrap();
        let r = report(&mut dev);
        assert!(!r.is_clean());
    }

    /// Random byte damage over the metadata (headers, bitmap, B-trees)
    /// must never panic verification or a resize plan, and every run
    /// stays within its bounds.
    #[test]
    fn random_metadata_damage_never_panics() {
        let base = sample(false);
        let mut vh = [0u8; 512];
        let mut d = MemoryBackend::from_bytes(base.as_slice().to_vec());
        d.read_at(1024, &mut vh).unwrap();
        let bs = u64::from(be32(&vh, 40));
        // Metadata lives in the first blocks of an fstool volume.
        let meta_end = (u64::from(fork_at(&vh, FORK_CATALOG).extents[0].start_block)
            + u64::from(fork_at(&vh, FORK_CATALOG).total_blocks))
            * bs;
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let opts = VerifyOpts {
            max_nodes: 10_000,
            max_records: 100_000,
            ..VerifyOpts::default()
        };
        for _ in 0..300 {
            let mut bytes = base.as_slice().to_vec();
            for _ in 0..(1 + next() % 16) {
                let off = (next() % meta_end) as usize;
                bytes[off] = next() as u8;
            }
            let mut dev = MemoryBackend::from_bytes(bytes);
            let r = verify(&mut dev, &opts).unwrap();
            assert!(r.stats.nodes <= 10_000 + 16);
            let _ = crate::fs::hfs_plus::resize::plan_resize(
                &mut dev,
                16 << 20,
                &crate::fs::hfs_plus::resize::ResizeOpts::default(),
            );
        }
    }

    #[test]
    fn bounds_truncate_explicitly() {
        let mut dev = sample(false);
        let opts = VerifyOpts {
            max_nodes: 2,
            max_diagnostics: 1,
            ..VerifyOpts::default()
        };
        let r = verify(&mut dev, &opts).unwrap();
        assert!(r.truncated.contains(&Truncation::Nodes));
        assert!(!r.is_clean());
        assert!(r.diagnostics.len() <= 1);
        // No spurious leaked-block errors from the incomplete walk.
        assert!(
            !r.diagnostics
                .iter()
                .any(|d| d.code == DiagCode::BitmapLeakedBlocks && d.severity == Severity::Error)
        );
    }
}
