//! APFS image writer — best-effort, single-volume, no checkpoint replay.
//!
//! ## Scope
//!
//! This produces a single-volume container that macOS mounts natively
//! (see `tests/apfs_mount_external.rs`), laid out the way `newfs_apfs`
//! lays one out: an NXSB at block 0 plus the live checkpoint inside the
//! checkpoint descriptor area, a container omap, a space manager with
//! its internal pool, a reaper, and one volume with its own omap, an
//! fs-tree (single- or multi-leaf), an extent-reference tree and an
//! empty snapshot-metadata tree, holding any number of regular files,
//! directories, symlinks and xattrs under the root directory (inode 2)
//! next to the private directory (inode 3).
//!
//! Layout (block numbers given for `block_size = 4096`; `D` is the
//! checkpoint data area's size, see `xp_data_blocks_for`):
//!
//! ```text
//!   0        NXSB           container label (copy of the live one)
//!   1        checkpoint_map (resolves the spaceman and reaper oids)
//!   2        NXSB           live checkpoint (xid=2)
//!   3..16    reserved xp_desc slots for future NXSB checkpoints
//!            (used by reopen-and-write — see [`crate::fs::apfs::Apfs::open_writable`])
//!  17        spaceman_phys  first block of the checkpoint data area
//!  18        reaper
//!  ..17+D    rest of the data area, left for the kernel's checkpoints
//!  +0        omap_phys_t    container omap header
//!  +1        APSB           volume superblock
//!  +2        omap_phys_t    volume omap header
//!  +3..      internal pool: 16-block IP-bitmap ring, then the pool
//!            proper (3 blocks per chunk + CIB) holding the CIB and the
//!            chunk bitmaps
//!  then      bump area — file data, then fs-tree, extent-ref and
//!            snapshot-metadata nodes and omap nodes
//! ```
//!
//! ## xp_desc area sizing
//!
//! The writer reserves `XP_DESC_BLOCKS` (16) blocks for the checkpoint
//! descriptor area instead of the bare minimum (2). The extra slots are
//! never used by `finish()` — they stay zeroed and are valid "no-op"
//! entries that the reader ignores when scanning for the latest-xid
//! NXSB. The reopen-and-write path
//! ([`crate::fs::apfs::Apfs::open_writable`]) consumes these slots one
//! per `sync()` so each new checkpoint goes at a fresh xp_desc block,
//! leaving the previous checkpoint's NXSB untouched (COW).
//!
//! ## Space manager
//!
//! The `spaceman` module emits the `spaceman_phys_t` `newfs_apfs`
//! writes for a fresh container: one device, a single chunk-info block
//! (CIB) listing one `chunk_info_t` per chunk (`8 * block_size`
//! blocks), each with an allocation bitmap where set bits mean "used",
//! all of them inside the internal pool; empty free queues with no
//! trees; and size-dependent limits the kernel recomputes and checks
//! (see `main_fq_node_limit`). The main bitmap marks the whole used
//! prefix — NXSB copies, the descriptor and data areas, the pool,
//! metadata and file data.
//!
//! On a checkpoint (the reopen-and-write path) the spaceman is not
//! rewritten, so it keeps describing the format-time allocations.
//!
//! ## Multi-leaf fs-tree
//!
//! When the staged fs-tree records overflow a single leaf, the writer
//! emits multiple leaf blocks (each ≤ `block_size - btree_info_t`) and
//! builds a single internal-node *root* above them. The internal root's
//! keys are the first record key of each leaf and its values are 8-byte
//! virtual oids; each leaf's vid is added to the volume omap so the
//! reader can resolve `(vid → paddr)` during descent. With ~4 KiB blocks
//! the internal root can address hundreds of leaves before it itself
//! overflows; if that ever happens, `finish` returns `Unsupported`.
//!
//! ## Multi-leaf omaps
//!
//! The container and volume omaps follow the same split rule, except the
//! internal-node child pointers are physical block addresses (the omap
//! is a physical tree, not virtual).
//!
//! ## Streaming invariant
//!
//! File bytes are copied through a 64 KiB scratch buffer; the writer
//! never loads a whole file into memory. Metadata blocks are each
//! bounded by `block_size`.
//!
//! ## Public API
//!
//! ```ignore
//! let mut w = ApfsWriter::new(&mut dev, total_blocks, 4096, "MyVolume")?;
//! let dir = w.add_dir(2, "subdir", 0o755)?;
//! w.add_file_from_reader(dir, "hello.txt", 0o644, &mut some_reader, size)?;
//! w.add_symlink(2, "link", 0o777, "target")?;
//! w.add_xattr(dir, "user.note", b"hello")?;
//! w.finish()?;
//! ```
//!
//! ## Limits
//!
//! - No checkpoint replay is performed (we don't pretend to be journal-
//!   recoverable).
//! - Multi-leaf trees can only have one internal level (root + leaves);
//!   if the internal root overflows, `finish` returns `Unsupported`.
//! - Xattr values larger than [`APFS_XATTR_MAX_EMBEDDED_SIZE`] (3804
//!   bytes) require a `j_xattr_dstream_t` referencing a separate
//!   dstream object. That layout is deferred — [`ApfsWriter::add_xattr`]
//!   returns `Unsupported` for oversized values.
//! - No snapshots, no encryption, no clones, no compression.
//! - The image must be at least ~32 blocks long.

use std::io::Read;

use crate::Result;
use crate::block::BlockDevice;

use super::btree::{BTNODE_FIXED_KV_SIZE, BTNODE_LEAF, BTNODE_ROOT, BTREE_INFO_SIZE};
use super::checksum::fletcher64;
use super::jrec::{
    APFS_TYPE_DIR_REC, APFS_TYPE_DSTREAM_ID, APFS_TYPE_FILE_EXTENT, APFS_TYPE_INODE,
    APFS_TYPE_XATTR, DT_DIR, DT_LNK, DT_REG, INO_EXT_TYPE_DSTREAM, J_INODE_VAL_FIXED_SIZE,
    OBJ_ID_MASK, OBJ_TYPE_SHIFT,
};
use super::obj::{
    OBJECT_TYPE_BTREE, OBJECT_TYPE_BTREE_NODE, OBJECT_TYPE_CHECKPOINT_MAP, OBJECT_TYPE_FS,
    OBJECT_TYPE_FSTREE, OBJECT_TYPE_NX_SUPERBLOCK, OBJECT_TYPE_OMAP,
};
use super::spaceman::{self, SPACEMAN_IP_BM_TX_MULTIPLIER, SpacemanLayout, blocks_per_chunk};
use super::superblock::{APFS_MAGIC, NX_MAGIC, NX_MAX_FILE_SYSTEMS};

/// `OBJ_VIRTUAL = 0` (the default flag); `OBJ_PHYSICAL = 0x4000_0000`;
/// `OBJ_EPHEMERAL = 0x8000_0000`. We use OBJ_PHYSICAL for everything
/// that lives at a fixed block address, OBJ_VIRTUAL (= 0) for omap-
/// resolved entities.
const OBJ_PHYSICAL: u32 = 0x4000_0000;
const OBJ_EPHEMERAL: u32 = 0x8000_0000;

/// 64 KiB scratch buffer for streamed file copies.
const COPY_BUF: usize = 64 * 1024;

/// Magic xid we use for every object we write. Larger than any plausible
/// label-NXSB xid (1) so our blocks "win" the most-recent-checkpoint
/// pick in the reader.
pub(crate) const WRITE_XID: u64 = 2;

/// Number of blocks reserved for the checkpoint descriptor area.
/// Sized to hold the chkmap stub (1 block), the live NXSB
/// (1 block), and 14 future-checkpoint NXSB slots for the
/// reopen-and-write path.
pub(crate) const XP_DESC_BLOCKS: u32 = 16;

/// Physical block of the chkmap stub (first xp_desc slot).
pub(crate) const CHKMAP_PADDR: u64 = 1;
/// Physical block of the initial live NXSB (second xp_desc slot).
pub(crate) const NXSB_LIVE_PADDR: u64 = 2;
/// Physical block of the spaceman_phys — the first block of the
/// checkpoint *data* area, which starts just past the xp_desc area.
pub(crate) const SPACEMAN_PADDR: u64 = (XP_DESC_BLOCKS as u64) + 1;
/// Smallest checkpoint data area (`nx_xp_data_blocks`) we emit.
/// `fsck_apfs` rejects a container whose data area is smaller than 8
/// blocks ("nx_xp_data_blocks (1) is less than 8"). Larger containers
/// get a proportionally larger area — see [`xp_data_blocks_for`].
pub(crate) const XP_DATA_BLOCKS_MIN: u32 = 8;
/// Blocks of the checkpoint data area a format-time checkpoint actually
/// uses: the spaceman and the reaper, in that order.
const XP_DATA_USED: u32 = 2;
/// Lowest possible first bump-allocated block: the data area at its
/// minimum size followed by the container omap header, the volume
/// superblock and the volume omap header.
pub(crate) const BUMP_BLOCK_START: u64 = SPACEMAN_PADDR + XP_DATA_BLOCKS_MIN as u64 + 3;

/// `sfq_tree_node_limit` of the main free queue for a container of
/// `total_blocks` 4 KiB blocks.
///
/// The macOS kernel recomputes this figure when it opens a container
/// and refuses one whose spaceman disagrees — in either direction — by
/// silently never bringing the container up (`diskutil` shows the
/// container with no physical store, error -69808). `fsck_apfs` does
/// not check it. The formula below reproduces what `newfs_apfs`
/// writes, measured at every transition point from one block to
/// 16 GiB: one node per 4544 blocks (32 × the 142 entries of a free
/// queue root node), but never exactly 2; one per 2272 blocks from
/// 1 GiB (262 144 blocks) on; and 512 from 4 GiB (1 048 576 blocks)
/// up.
fn main_fq_node_limit(total_blocks: u64) -> u16 {
    let limit = match total_blocks {
        b if b >= 1 << 20 => 512,
        b if b >= 1 << 18 => b.div_ceil(2272),
        b => match b.div_ceil(4544) {
            2 => 3,
            n => n.max(1),
        },
    };
    limit.min(512) as u16
}

/// Size of the checkpoint data area for a container of `total_blocks`
/// blocks. The area holds the ephemeral objects of the live checkpoint
/// *and* of the previous one — the spaceman, the reaper and the
/// spaceman's free-queue trees, which the kernel creates there once it
/// starts freeing blocks and which may grow to the free queues' node
/// limits — so it scales with the main free queue's limit `L` the way
/// `newfs_apfs`'s does: `16 + 36·L` blocks up to `L = 8`, then
/// `272 + 4·L`. (macOS accepts other sizes too, as long as the area
/// overlaps nothing.) Containers too small for that keep at least
/// [`XP_DATA_BLOCKS_MIN`].
pub(crate) fn xp_data_blocks_for(total_blocks: u64) -> u32 {
    let l = main_fq_node_limit(total_blocks) as u64;
    let native = if l <= 8 { 16 + 36 * l } else { 272 + 4 * l };
    native.min(total_blocks / 8).max(XP_DATA_BLOCKS_MIN as u64) as u32
}

/// Blocks the space manager's internal pool occupies on format: the
/// IP-bitmap ring followed by the pool proper. It sits right after the
/// container omap header, the APSB and the volume omap header, ahead of
/// the bump area — where `newfs_apfs` puts it, just past the checkpoint
/// data area.
fn internal_pool_span(total_blocks: u64, block_size: u32) -> u64 {
    let chunks = total_blocks.div_ceil(blocks_per_chunk(block_size as usize));
    SPACEMAN_IP_BM_TX_MULTIPLIER as u64 + spaceman::ip_block_count(chunks)
}

/// `INODE_NO_RSRC_FORK` in `j_inode_val_t.internal_flags`.
const INODE_NO_RSRC_FORK: u64 = 0x0000_8000;

/// `XF_SYSTEM_FIELD` — `x_field_t.x_flags` bit for fields the
/// filesystem owns (the data stream among them).
const XF_SYSTEM_FIELD: u8 = 0x20;

/// `XATTR_DATA_EMBEDDED` flag in `j_xattr_val_t.flags`. When set the
/// xattr value is stored inline immediately after the val header.
const XATTR_DATA_EMBEDDED: u16 = 0x0002;

/// `XATTR_FILE_SYSTEM_OWNED` — the xattr belongs to the filesystem
/// rather than to the user, so it doesn't show up in `listxattr`.
/// Apple sets it on `com.apple.fs.symlink`.
const XATTR_FILE_SYSTEM_OWNED: u16 = 0x0004;

/// Where APFS keeps a symbolic link's target: an embedded,
/// filesystem-owned xattr on the link's inode holding the target path
/// with a trailing NUL. There is no data stream — the inode carries no
/// `INO_EXT_TYPE_DSTREAM` xfield and its size is zero.
pub const APFS_SYMLINK_XATTR: &str = "com.apple.fs.symlink";

/// Hard cap on the embedded-xattr value size, taken from the Apple File
/// System Reference (constant `APFS_XATTR_MAX_EMBEDDED_SIZE`). Values up
/// to and including this size can be stored inline; larger ones require
/// a `j_xattr_dstream_t` (not implemented).
pub const APFS_XATTR_MAX_EMBEDDED_SIZE: usize = 3804;

/// Descriptor slots one checkpoint occupies: one checkpoint-map block
/// plus the superblock that follows it.
pub(crate) const CHECKPOINT_DESC_SLOTS: u32 = 2;

/// Reserved object id of the container superblock (`OID_NX_SUPERBLOCK`
/// in the Apple File System Reference). Every NXSB copy carries it in
/// `o_oid`, whatever block it lives on.
const OID_NX_SUPERBLOCK: u64 = 1;

/// `BTOFF_INVALID` — the "this free list is empty" offset marker.
const BTOFF_INVALID: u16 = 0xFFFF;

/// `nx_ephemeral_info[0]` without its minimum block count:
/// `(NX_MAX_FILE_SYSTEM_EPH_STRUCTS 4 << 16) | NX_EPHEMERAL_INFO_VERSION_1`.
/// [`ApfsWriter::build_nxsb`] ORs `min_block_count << 32` in.
const NX_EPHEMERAL_INFO_0: u64 = 0x0000_0000_0004_0001;

/// `NX_INCOMPAT_VERSION2` — the container uses APFS version 2.
const NX_INCOMPAT_VERSION2: u64 = 0x0000_0000_0000_0002;

/// `OMAP_MANUALLY_MANAGED` — set on the container omap, which never
/// carries snapshots.
const OMAP_MANUALLY_MANAGED: u32 = 0x0000_0001;

/// `OBJECT_TYPE_NX_REAPER` from the Apple File System Reference.
const OBJECT_TYPE_NX_REAPER: u32 = 0x0000_0011;

/// First virtual oid we assign to fs-tree leaves. We start well past the
/// reserved-range used by other writer constants.
const FS_LEAF_VID_BASE: u64 = 0x1_0000;

/// `ROOT_DIR_PARENT`: the parent inode number of the root directory.
/// It has no inode record of its own.
const ROOT_DIR_PARENT: u64 = 1;
/// `ROOT_DIR_INO_NUM`.
const ROOT_DIR_INO_NUM: u64 = 2;
/// `PRIV_DIR_INO_NUM`: the volume's private directory.
const PRIV_DIR_INO_NUM: u64 = 3;

/// One pending fs-tree record (key + value bytes), used by the in-memory
/// builder before serialization.
#[derive(Clone)]
struct FsRecord {
    key: Vec<u8>,
    val: Vec<u8>,
}

/// APFS fs-tree record order: ascending oid, then ascending record
/// type, then a type-specific tail — the same rules the reader's
/// `cmp_fs_key` and macOS apply. Directory entries sort by name
/// (plain keys) or by hash then name (hashed keys), never by their
/// length prefix; file extents by their logical offset as a number;
/// xattrs by name.
fn fs_record_cmp(a: &FsRecord, b: &FsRecord, hashed_drecs: bool) -> std::cmp::Ordering {
    let ha = u64::from_le_bytes(a.key[0..8].try_into().unwrap());
    let hb = u64::from_le_bytes(b.key[0..8].try_into().unwrap());
    let kind = (ha >> OBJ_TYPE_SHIFT) as u8;
    let head = (ha & OBJ_ID_MASK, kind).cmp(&(hb & OBJ_ID_MASK, (hb >> OBJ_TYPE_SHIFT) as u8));
    if head != std::cmp::Ordering::Equal {
        return head;
    }
    let (ta, tb) = (&a.key[8..], &b.key[8..]);
    let u16_name = |t: &[u8]| t.get(2..).unwrap_or(&[]).to_vec();
    match kind {
        APFS_TYPE_DIR_REC if hashed_drecs => {
            let hash = |t: &[u8]| {
                t.get(0..4)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()) & !0x3ff)
                    .unwrap_or(0)
            };
            let name = |t: &[u8]| t.get(4..).unwrap_or(&[]).to_vec();
            (hash(ta), name(ta)).cmp(&(hash(tb), name(tb)))
        }
        APFS_TYPE_DIR_REC | APFS_TYPE_XATTR => u16_name(ta).cmp(&u16_name(tb)),
        APFS_TYPE_FILE_EXTENT if ta.len() >= 8 && tb.len() >= 8 => {
            let off = |t: &[u8]| u64::from_le_bytes(t[0..8].try_into().unwrap());
            off(ta).cmp(&off(tb))
        }
        _ => ta.cmp(tb),
    }
}

/// A streaming APFS writer. Construct one with [`ApfsWriter::new`],
/// build the filesystem tree with [`ApfsWriter::add_file_from_reader`],
/// [`ApfsWriter::add_dir`], [`ApfsWriter::add_symlink`], and
/// [`ApfsWriter::add_xattr`], then call [`ApfsWriter::finish`] to
/// materialise the on-disk image.
///
/// The writer owns a `&mut BlockDevice`; the device must already be
/// sized large enough (zero-extended is fine — we'll overwrite the
/// header and any blocks we use).
pub struct ApfsWriter<'a> {
    dev: &'a mut dyn BlockDevice,
    block_size: u32,
    total_blocks: u64,
    /// Index of the next free metadata/data block (bump-pointer allocated
    /// from `bump_block_start`). Metadata extents are reserved before
    /// data extents inside `finish()` by pre-incrementing this counter
    /// for each fs-tree / omap leaf we need.
    next_block: u64,
    /// First block reserved for bump allocation (metadata leaves + file
    /// extents). The fixed-position blocks (NXSB copies, chkmap,
    /// spaceman, container/volume omap headers, APSB) all live below
    /// this.
    bump_block_start: u64,
    /// Volume name, written into the APSB.
    volume_name: String,
    /// Container UUID (random-ish — derived from the volume name).
    container_uuid: [u8; 16],
    /// Volume UUID (derived from volume name + a salt).
    volume_uuid: [u8; 16],
    /// Pending fs-tree records, sorted on `finish()`.
    records: Vec<FsRecord>,
    /// Next free inode object id. Inode 2 is the root directory.
    next_oid: u64,
    /// Number of files added (for APSB stats).
    num_files: u64,
    /// Number of directories added beyond the root (for APSB stats).
    num_directories: u64,
    /// Number of symlinks added (for APSB stats).
    num_symlinks: u64,
    /// True once `finish()` has been called.
    finished: bool,
    /// XID stamped on every emitted block. Defaults to [`WRITE_XID`] for
    /// fresh `format`-driven writers; the reopen-and-write path bumps
    /// this for each subsequent checkpoint via [`ApfsWriter::new_checkpoint`].
    xid: u64,
    /// Block address where the new NXSB will be written. The format
    /// path uses [`NXSB_LIVE_PADDR`]; reopen-and-write picks the next
    /// free slot in the xp_desc area.
    nxsb_paddr: u64,
    /// True when the label NXSB at block 0 should be refreshed (only on
    /// format).
    write_label_nxsb: bool,
    /// Live APSB bytes to patch instead of building one from a fixed
    /// template. `None` on the format path (there is nothing to carry
    /// forward yet); `Some` on every checkpoint, so the volume's
    /// feature flags, `apfs_incompatible_features`, extentref /
    /// snapshot-metadata tree oids, role and encryption state survive
    /// the rewrite. See [`ApfsWriter::build_apsb`].
    apsb_template: Option<Vec<u8>>,
    /// Live NXSB bytes, carried the same way. See
    /// [`ApfsWriter::build_nxsb`].
    nxsb_template: Option<Vec<u8>>,
    /// Which `nx_fs_oid[]` slot the volume being rewritten occupies.
    volume_index: usize,
    /// `nx_xp_data_blocks`: size of the checkpoint data area, which
    /// starts at [`SPACEMAN_PADDR`]. Chosen by [`xp_data_blocks_for`]
    /// on format, carried over from the live superblock on a
    /// checkpoint.
    xp_data_blocks: u32,
}

// ───────────────────────── shared record builders ─────────────────────────
//
// Free `pub(crate)` functions that build the on-disk (key, value) byte
// pairs for every fs-tree record kind we emit. Both the single-pass
// [`ApfsWriter`] (format / pending-write path) and the in-place mutators
// in [`super::Apfs`] (Write-state checkpoint COWs via
// [`super::rw::commit_with_mutator`]) push records through the same
// builders, so the byte layouts only need to live in one place.

/// Build the `j_drec_key_t` (plain) or `j_drec_hashed_key_t` (hashed)
/// key + `j_drec_val_t` value bytes for a directory entry. The
/// layout follows the volume's `apfs_incompatible_features` flags:
///
/// - `Plain` (the default for volumes our own writer formats):
///   `(hdr:u64, name_len:u16, name + NUL)`. Sort order in the
///   fs-tree is by (oid, kind, name).
/// - `Hashed` (set by `APFS_INCOMPAT_NORMALIZATION_INSENSITIVE`,
///   the macOS default for user data volumes):
///   `(hdr:u64, name_len_and_hash:u32 LE, name + NUL)`. Sort order
///   is by (oid, kind, hash, name). The hash is computed by
///   [`apfs_drec_name_len_and_hash`] from the NFD-normalised
///   (optionally case-folded per `case_fold`) name.
///
/// Value bytes are layout-independent.
///
/// Errors when the name is too long to encode in the 16-bit or
/// 10-bit `name_len` field, depending on layout — POSIX caps at
/// 255 bytes anyway, but the type allows more.
pub(crate) fn build_drec_record(
    parent_oid: u64,
    name: &str,
    target_oid: u64,
    dtype: u16,
    layout: super::fstree::DrecKeyLayout,
    case_fold: bool,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let nlen = name.len() + 1; // includes trailing NUL
    let mut key;
    let hdr = ((APFS_TYPE_DIR_REC as u64) << OBJ_TYPE_SHIFT) | (parent_oid & OBJ_ID_MASK);
    match layout {
        super::fstree::DrecKeyLayout::Plain => {
            if nlen > u16::MAX as usize {
                return Err(crate::Error::InvalidArgument(
                    "apfs writer: directory entry name too long".into(),
                ));
            }
            key = Vec::with_capacity(10 + nlen);
            key.extend_from_slice(&hdr.to_le_bytes());
            key.extend_from_slice(&(nlen as u16).to_le_bytes());
        }
        super::fstree::DrecKeyLayout::Hashed => {
            // Hashed layout packs (hash:22, name_len:10) into a u32.
            if nlen > 0x3FF {
                return Err(crate::Error::InvalidArgument(
                    "apfs writer: hashed-key directory entry name too long".into(),
                ));
            }
            key = Vec::with_capacity(12 + nlen);
            key.extend_from_slice(&hdr.to_le_bytes());
            let packed = apfs_drec_name_len_and_hash(name, case_fold);
            key.extend_from_slice(&packed.to_le_bytes());
        }
    }
    key.extend_from_slice(name.as_bytes());
    key.push(0);

    // j_drec_val_t: file_id u64 + date_added u64 (zero) + flags u16
    let mut val = vec![0u8; 18];
    val[0..8].copy_from_slice(&target_oid.to_le_bytes());
    val[16..18].copy_from_slice(&dtype.to_le_bytes());
    Ok((key, val))
}

/// Pack a drec's name length and 22-bit hash into the `u32 LE` that
/// lives in `j_drec_hashed_key_t.name_len_and_hash`. The hash is
/// CRC-32C over the NFD-decomposed (and optionally case-folded) name
/// encoded as UTF-32 LE, seeded with `0xFFFFFFFF` and **not** inverted
/// at the end (what the kernel and the Linux apfs driver compute —
/// the finalised CRC-32C is its bitwise complement, so this is
/// `!crc32c(..)`); low 10 bits of the result are the raw name length
/// **including** the trailing NUL. Verified against drecs written by
/// macOS (`hdiutil create -srcfolder`).
///
/// Best-effort match for Apple's kernel hash: ASCII and common BMP
/// names match byte-for-byte. Uncommon combining sequences and
/// supplementary-plane characters may differ because Apple's
/// `UnicodeTables_v10.h` carries documented deviations (4-char
/// decomposition cap, iota-subscript CCC override, restricted
/// codepoint domain) we don't reproduce. If a name's hash diverges
/// from the kernel's, the new drec sorts into the wrong B-tree
/// bucket and the kernel won't find it on the next mount — same
/// failure mode as an off-by-one in our impl.
pub fn apfs_drec_name_len_and_hash(name: &str, case_fold: bool) -> u32 {
    use intl::unicode::{case, normalize};
    // NFD first, then fold — the order the kernel's hash uses. Both are
    // iterator adapters, so nothing intermediate is allocated.
    let chars: Vec<u32> = if case_fold {
        case::fold(normalize::nfd(name.chars()))
            .map(|c| c as u32)
            .collect()
    } else {
        normalize::nfd(name.chars()).map(|c| c as u32).collect()
    };
    let bytes: Vec<u8> = chars.iter().flat_map(|c| c.to_le_bytes()).collect();
    // `crc32c` is the finalised flavour (seed !0, final XOR !0); APFS
    // stores the un-finalised register, i.e. its complement.
    let crc = !crate::crc::crc32c(&bytes);
    let name_len = (name.len() + 1) as u32; // include trailing NUL
    ((crc & 0x003F_FFFF) << 10) | (name_len & 0x0000_03FF)
}

/// Build the `j_inode_key_t` + `j_inode_val_t` record bytes. For
/// regular files / symlinks (`dstream_size > 0` OR mode is `S_IFREG` /
/// `S_IFLNK`) an `INO_EXT_TYPE_DSTREAM` xfield carrying `size` and
/// `alloced_size` (block-rounded) is appended. Directory inodes get
/// no xfield. `nlink` is seeded as 2 for directories and 1 for
/// everything else, matching the single-pass writer's convention.
///
/// `block_size` is needed to round `alloced_size` to a whole-block
/// boundary inside the DSTREAM xfield value.
pub(crate) fn build_inode_record(
    oid: u64,
    parent_oid: u64,
    mode: u16,
    dstream_size: u64,
    block_size: u32,
    mtime_ns: u64,
) -> (Vec<u8>, Vec<u8>) {
    // Regular files always carry a dstream, even an empty one.
    // Symlinks never do: their target lives in the
    // `com.apple.fs.symlink` xattr and their size is zero, which is
    // what macOS writes and what its VFS expects to read back.
    let is_symlink = mode & 0o170_000 == 0o120_000;
    let has_dstream = !is_symlink && (dstream_size > 0 || (mode & 0o170_000 == 0o100_000));
    let mut val = vec![0u8; J_INODE_VAL_FIXED_SIZE];
    val[0..8].copy_from_slice(&parent_oid.to_le_bytes());
    // `private_id` is the inode's own id for every inode — directories
    // and symlinks included — exactly as macOS writes it; for files it
    // doubles as the default data stream's id.
    val[8..16].copy_from_slice(&oid.to_le_bytes());
    // Stamp all four time fields with `mtime_ns`. APFS records
    // create_time/mod_time/change_time/access_time as four separate
    // u64-ns slots; we collapse them to a single value because most
    // callers only have an mtime to give. Per-field timestamps can
    // be refined later via Apfs::set_times / Filesystem::set_attrs.
    val[16..24].copy_from_slice(&mtime_ns.to_le_bytes()); // create_time
    val[24..32].copy_from_slice(&mtime_ns.to_le_bytes()); // mod_time
    val[32..40].copy_from_slice(&mtime_ns.to_le_bytes()); // change_time
    val[40..48].copy_from_slice(&mtime_ns.to_le_bytes()); // access_time
    // internal_flags: INODE_NO_RSRC_FORK — macOS sets it on every
    // inode without a resource fork, and fsck_apfs asks for it.
    val[48..56].copy_from_slice(&INODE_NO_RSRC_FORK.to_le_bytes());
    // `nchildren` for a directory (filled in by the writer from the
    // record set it finally commits), `nlink` for everything else.
    let nlink: i32 = if mode & 0o170_000 == 0o040_000 { 0 } else { 1 };
    val[56..60].copy_from_slice(&nlink.to_le_bytes());
    // owner/group: 0 (root).
    val[80..82].copy_from_slice(&mode.to_le_bytes());
    // uncompressed_size (84..92) stays 0: it is only meaningful with
    // INODE_HAS_UNCOMPRESSED_SIZE (decmpfs files). The size lives in
    // the DSTREAM xfield.

    if has_dstream {
        // xfield blob: 1 entry (DSTREAM), 40 bytes value, padded to 8.
        let mut xfields = Vec::new();
        xfields.extend_from_slice(&1u16.to_le_bytes()); // num_exts
        xfields.extend_from_slice(&40u16.to_le_bytes()); // used_data
        // x_field_t = (type:u8, flags:u8, size:u16). The data stream
        // is a system field (`XF_SYSTEM_FIELD`), as macOS marks it.
        xfields.push(INO_EXT_TYPE_DSTREAM);
        xfields.push(XF_SYSTEM_FIELD);
        xfields.extend_from_slice(&40u16.to_le_bytes());
        // value: j_dstream_t (40 bytes)
        let mut ds = [0u8; 40];
        ds[0..8].copy_from_slice(&dstream_size.to_le_bytes());
        let bs = block_size as u64;
        let alloc = dstream_size.div_ceil(bs) * bs;
        ds[8..16].copy_from_slice(&alloc.to_le_bytes());
        xfields.extend_from_slice(&ds);
        val.extend_from_slice(&xfields);
    }

    let mut key = vec![0u8; 8];
    let hdr = ((APFS_TYPE_INODE as u64) << OBJ_TYPE_SHIFT) | (oid & OBJ_ID_MASK);
    key.copy_from_slice(&hdr.to_le_bytes());
    (key, val)
}

/// Build the FILE_EXTENT + DSTREAM_ID record pair for a single extent
/// of `dstream_oid`. Always returns two records — the FILE_EXTENT
/// carrying `(logical_addr, length, phys_block)` and the DSTREAM_ID
/// counter the reader uses to locate the dstream's extents under this
/// oid.
pub(crate) fn build_file_extent_records(
    dstream_oid: u64,
    logical_addr: u64,
    length: u64,
    phys_block: u64,
    block_size: u32,
) -> [(Vec<u8>, Vec<u8>); 2] {
    // FILE_EXTENT
    let mut fe_key = vec![0u8; 16];
    let fe_hdr = ((APFS_TYPE_FILE_EXTENT as u64) << OBJ_TYPE_SHIFT) | (dstream_oid & OBJ_ID_MASK);
    fe_key[0..8].copy_from_slice(&fe_hdr.to_le_bytes());
    fe_key[8..16].copy_from_slice(&logical_addr.to_le_bytes());
    let mut fe_val = vec![0u8; 24];
    let bs = block_size as u64;
    let alloc = length.div_ceil(bs) * bs;
    fe_val[0..8].copy_from_slice(&alloc.to_le_bytes()); // length (low 56 bits)
    fe_val[8..16].copy_from_slice(&phys_block.to_le_bytes());
    // crypto_id stays zero.

    // DSTREAM_ID: `j_dstream_id_val_t.refcnt` — one reference (the
    // inode). macOS treats a zero-refcount stream as already deleted.
    let mut ds_key = vec![0u8; 8];
    let ds_hdr = ((APFS_TYPE_DSTREAM_ID as u64) << OBJ_TYPE_SHIFT) | (dstream_oid & OBJ_ID_MASK);
    ds_key.copy_from_slice(&ds_hdr.to_le_bytes());
    let ds_val = 1u32.to_le_bytes().to_vec();
    [(fe_key, fe_val), (ds_key, ds_val)]
}

/// Build an XATTR record for `(parent_oid, name, value)`. Embedded
/// values only — values larger than [`APFS_XATTR_MAX_EMBEDDED_SIZE`]
/// (3804 bytes) are rejected (dstream-backed xattrs are not yet
/// supported). Errors on a name that doesn't fit in a 16-bit
/// `name_len` field.
pub(crate) fn build_xattr_record(
    parent_oid: u64,
    name: &str,
    value: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    if value.len() > APFS_XATTR_MAX_EMBEDDED_SIZE {
        return Err(crate::Error::Unsupported(format!(
            "apfs writer: xattr value of {} bytes exceeds embedded limit ({}); \
             dstream xattrs are not supported",
            value.len(),
            APFS_XATTR_MAX_EMBEDDED_SIZE
        )));
    }
    let name_bytes = name.as_bytes();
    let nlen = name_bytes.len() + 1; // includes trailing NUL
    if nlen > u16::MAX as usize {
        return Err(crate::Error::InvalidArgument(
            "apfs writer: xattr name too long".into(),
        ));
    }
    // Key: j_xattr_key_t
    let mut key = Vec::with_capacity(10 + nlen);
    let hdr = ((APFS_TYPE_XATTR as u64) << OBJ_TYPE_SHIFT) | (parent_oid & OBJ_ID_MASK);
    key.extend_from_slice(&hdr.to_le_bytes());
    key.extend_from_slice(&(nlen as u16).to_le_bytes());
    key.extend_from_slice(name_bytes);
    key.push(0);
    // Value: j_xattr_val_t
    let mut val = Vec::with_capacity(4 + value.len());
    val.extend_from_slice(&XATTR_DATA_EMBEDDED.to_le_bytes());
    val.extend_from_slice(&(value.len() as u16).to_le_bytes());
    val.extend_from_slice(value);
    Ok((key, val))
}

/// Build the `com.apple.fs.symlink` xattr record that carries a
/// symbolic link's target. The stored value is the target bytes plus a
/// trailing NUL, flagged embedded + filesystem-owned — byte-identical
/// to what macOS writes.
pub(crate) fn build_symlink_xattr_record(oid: u64, target: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut value = Vec::with_capacity(target.len() + 1);
    value.extend_from_slice(target.as_bytes());
    value.push(0);
    let (key, mut val) = build_xattr_record(oid, APFS_SYMLINK_XATTR, &value)?;
    val[0..2].copy_from_slice(&(XATTR_DATA_EMBEDDED | XATTR_FILE_SYSTEM_OWNED).to_le_bytes());
    Ok((key, val))
}

impl<'a> ApfsWriter<'a> {
    /// Create a writer over `dev`. `total_blocks * block_size` must fit
    /// inside `dev.total_size()`. `block_size` must be a power of two
    /// between 512 and 65 536; APFS in the wild is always 4096.
    pub fn new(
        dev: &'a mut dyn BlockDevice,
        total_blocks: u64,
        block_size: u32,
        volume_name: &str,
    ) -> Result<Self> {
        if !(512..=65_536).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(crate::Error::InvalidArgument(format!(
                "apfs writer: block_size {block_size} is not a sensible power of two"
            )));
        }
        let needed = total_blocks.checked_mul(block_size as u64).ok_or_else(|| {
            crate::Error::InvalidArgument("apfs writer: total_blocks * block_size overflows".into())
        })?;
        if needed > dev.total_size() {
            return Err(crate::Error::InvalidArgument(format!(
                "apfs writer: image needs {} bytes but dev is {} bytes",
                needed,
                dev.total_size()
            )));
        }
        // The minimum (~32 blocks) accommodates the expanded
        // xp_desc area plus the fixed-prefix metadata blocks plus
        // enough bump room for a one-record fs-tree.
        if total_blocks < 64 {
            return Err(crate::Error::InvalidArgument(
                "apfs writer: need at least 64 blocks".into(),
            ));
        }
        let container_uuid = derive_uuid(volume_name.as_bytes(), b"container");
        let volume_uuid = derive_uuid(volume_name.as_bytes(), b"volume");

        // See module-level layout: the checkpoint data area, then the
        // container omap header, the APSB and the volume omap header,
        // then the bump area.
        let xp_data_blocks = xp_data_blocks_for(total_blocks);
        let bump_block_start: u64 = SPACEMAN_PADDR
            + xp_data_blocks as u64
            + 3
            + internal_pool_span(total_blocks, block_size);
        let mut w = Self {
            dev,
            block_size,
            total_blocks,
            next_block: bump_block_start,
            bump_block_start,
            volume_name: volume_name.to_string(),
            container_uuid,
            volume_uuid,
            records: Vec::new(),
            next_oid: 16, // inode 2 is root; we hand out 16+ for new inodes
            num_files: 0,
            num_directories: 0,
            num_symlinks: 0,
            finished: false,
            xid: WRITE_XID,
            nxsb_paddr: NXSB_LIVE_PADDR,
            write_label_nxsb: true,
            apsb_template: None,
            nxsb_template: None,
            volume_index: 0,
            xp_data_blocks,
        };
        // Seed the two directories every APFS volume starts with: the
        // root (inode 2) and the private directory (inode 3), both
        // children of the pseudo-parent `ROOT_DIR_PARENT` (1), with
        // their directory entries — what `newfs_apfs` writes. Times
        // stay at 0 (epoch 1970) at format — callers refine via
        // set_times / set_attrs.
        w.add_drec(ROOT_DIR_PARENT, "private-dir", PRIV_DIR_INO_NUM, DT_DIR)?;
        w.add_drec(ROOT_DIR_PARENT, "root", ROOT_DIR_INO_NUM, DT_DIR)?;
        w.add_inode_record(ROOT_DIR_INO_NUM, ROOT_DIR_PARENT, mode_dir(0o755), 0, 0)?;
        w.add_inode_record(PRIV_DIR_INO_NUM, ROOT_DIR_PARENT, mode_dir(0o644), 0, 0)?;
        Ok(w)
    }

    /// Construct a "checkpoint refresh" writer that emits a brand-new
    /// NXSB + fs-tree + omap snapshot of the volume's state into fresh
    /// blocks past `bump_block_start` and a new xp_desc slot at
    /// `nxsb_paddr`. Used by the reopen-and-write path
    /// ([`crate::fs::apfs::Apfs::open_writable`]).
    ///
    /// Unlike [`ApfsWriter::new`], this constructor does not seed any
    /// records — the caller is expected to push the full record set
    /// gathered from the existing fs-tree before calling
    /// [`ApfsWriter::finish`]. The label NXSB at block 0 is left
    /// untouched (only the new xp_desc slot is written), so a crash
    /// part-way through a checkpoint leaves the previous valid
    /// checkpoint discoverable.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_checkpoint(
        dev: &'a mut dyn BlockDevice,
        total_blocks: u64,
        block_size: u32,
        volume_name: &str,
        container_uuid: [u8; 16],
        volume_uuid: [u8; 16],
        xid: u64,
        nxsb_paddr: u64,
        bump_block_start: u64,
        next_oid: u64,
        num_files: u64,
        num_directories: u64,
        num_symlinks: u64,
        apsb_template: Vec<u8>,
        nxsb_template: Vec<u8>,
        volume_index: usize,
    ) -> Result<Self> {
        if !(512..=65_536).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(crate::Error::InvalidArgument(format!(
                "apfs writer: block_size {block_size} is not a sensible power of two"
            )));
        }
        if bump_block_start < BUMP_BLOCK_START || bump_block_start >= total_blocks {
            return Err(crate::Error::InvalidArgument(format!(
                "apfs writer: bump_block_start {bump_block_start} out of range \
                 [{BUMP_BLOCK_START}, {total_blocks})"
            )));
        }
        // Valid NXSB slot range: [NXSB_LIVE_PADDR, XP_DESC_BLOCKS+1).
        // NXSB_LIVE_PADDR (= 2) is the format-time slot, reusable
        // once the xp_desc ring wraps around. Slot 0 (block 1 =
        // CHKMAP_PADDR) is reserved for the chkmap and out of the
        // range. XP_DESC_BLOCKS = 16, base = 1, so the last valid
        // paddr is 16.
        if nxsb_paddr < NXSB_LIVE_PADDR || nxsb_paddr >= (XP_DESC_BLOCKS as u64 + 1) {
            return Err(crate::Error::InvalidArgument(format!(
                "apfs writer: nxsb_paddr {nxsb_paddr} not a valid xp_desc slot \
                 (expected {} ≤ slot < {})",
                NXSB_LIVE_PADDR,
                XP_DESC_BLOCKS as u64 + 1
            )));
        }
        // Keep the live checkpoint's data-area geometry.
        let xp_data_blocks = nxsb_template
            .get(108..112)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .filter(|&n| n >= XP_DATA_BLOCKS_MIN)
            .unwrap_or(XP_DATA_BLOCKS_MIN);
        Ok(Self {
            dev,
            block_size,
            total_blocks,
            next_block: bump_block_start,
            bump_block_start,
            volume_name: volume_name.to_string(),
            container_uuid,
            volume_uuid,
            records: Vec::new(),
            next_oid,
            num_files,
            num_directories,
            num_symlinks,
            finished: false,
            xid,
            nxsb_paddr,
            write_label_nxsb: false,
            apsb_template: Some(apsb_template),
            nxsb_template: Some(nxsb_template),
            volume_index,
            xp_data_blocks,
        })
    }

    /// Push a pre-built fs-tree record into the writer's record buffer.
    /// Used by the reopen-and-write path to inject the records dumped
    /// from the existing fs-tree.
    pub(crate) fn push_raw_record(&mut self, key: Vec<u8>, val: Vec<u8>) {
        self.records.push(FsRecord { key, val });
    }

    /// Add an empty subdirectory under `parent_oid`. Returns the new
    /// directory's object id (use it as `parent_oid` for nested
    /// children).
    pub fn add_dir(&mut self, parent_oid: u64, name: &str, mode: u16) -> Result<u64> {
        self.add_dir_at_time(parent_oid, name, mode, 0)
    }

    /// Like [`Self::add_dir`] but stamps `mtime_ns` (UNIX ns since
    /// epoch) into the inode's four time fields. Used by callers
    /// that carry user-supplied timestamps through to the writer
    /// (the [`crate::fs::Filesystem`] adapter, mainly).
    pub fn add_dir_at_time(
        &mut self,
        parent_oid: u64,
        name: &str,
        mode: u16,
        mtime_ns: u64,
    ) -> Result<u64> {
        let oid = self.alloc_oid();
        self.add_drec(parent_oid, name, oid, DT_DIR)?;
        self.add_inode_record(oid, parent_oid, mode_dir(mode), 0, mtime_ns)?;
        self.num_directories += 1;
        Ok(oid)
    }

    /// Add a symlink under `parent_oid`. The target goes into the
    /// `com.apple.fs.symlink` xattr on the link's inode — where APFS
    /// keeps it, and the only place macOS looks. The inode itself has
    /// no data stream and zero size; the drec's DT_LNK type bit is what
    /// makes directory listings report it as a symlink.
    pub fn add_symlink(
        &mut self,
        parent_oid: u64,
        name: &str,
        mode: u16,
        target: &str,
    ) -> Result<u64> {
        self.add_symlink_at_time(parent_oid, name, mode, target, 0)
    }

    /// Like [`Self::add_symlink`] but stamps `mtime_ns` into the
    /// inode's time fields.
    pub fn add_symlink_at_time(
        &mut self,
        parent_oid: u64,
        name: &str,
        mode: u16,
        target: &str,
        mtime_ns: u64,
    ) -> Result<u64> {
        let oid = self.alloc_oid();
        self.add_drec(parent_oid, name, oid, DT_LNK)?;
        self.add_inode_record(oid, parent_oid, mode_lnk(mode), 0, mtime_ns)?;
        let (k, v) = build_symlink_xattr_record(oid, target)?;
        self.records.push(FsRecord { key: k, val: v });
        self.num_symlinks += 1;
        Ok(oid)
    }

    /// Add a regular file under `parent_oid`. Bytes are streamed from
    /// `reader` through a 64 KiB scratch buffer into a freshly
    /// allocated single extent.
    ///
    /// `size` MUST match the byte count produced by `reader`. We trust
    /// the caller — if they overshoot or undershoot, the on-disk
    /// inode's `j_dstream.size` may not agree with the actual extent.
    pub fn add_file_from_reader<R: Read>(
        &mut self,
        parent_oid: u64,
        name: &str,
        mode: u16,
        reader: &mut R,
        size: u64,
    ) -> Result<u64> {
        self.add_file_from_reader_at_time(parent_oid, name, mode, reader, size, 0)
    }

    /// Like [`Self::add_file_from_reader`] but stamps `mtime_ns`
    /// into the inode's time fields.
    pub fn add_file_from_reader_at_time<R: Read>(
        &mut self,
        parent_oid: u64,
        name: &str,
        mode: u16,
        reader: &mut R,
        size: u64,
        mtime_ns: u64,
    ) -> Result<u64> {
        let oid = self.alloc_oid();
        self.add_drec(parent_oid, name, oid, DT_REG)?;

        if size == 0 {
            // No extent records — empty file.
            self.add_inode_record(oid, parent_oid, mode_reg(mode), 0, mtime_ns)?;
            self.num_files += 1;
            return Ok(oid);
        }

        let extent_paddr = self.allocate_extent_for_size(size)?;
        let blocks = self.bytes_to_blocks(size);

        // Stream the file into the allocated extent, block at a time.
        let mut block_buf = vec![0u8; self.block_size as usize];
        let mut scratch = vec![0u8; COPY_BUF];
        let mut bytes_left = size;
        let mut block_idx: u64 = 0;
        let mut block_off: usize = 0;
        block_buf.fill(0);
        while bytes_left > 0 {
            let want = scratch.len().min(bytes_left as usize);
            // Fully fill `scratch[..want]` even if reader returns short.
            let mut got = 0;
            while got < want {
                let n = reader
                    .read(&mut scratch[got..want])
                    .map_err(crate::Error::Io)?;
                if n == 0 {
                    break;
                }
                got += n;
            }
            if got == 0 {
                // Reader truncated — pad remaining file with zeros so
                // the on-disk size matches `size`.
                break;
            }
            // Copy `got` bytes into the per-block buffer, flushing when
            // it fills.
            let mut consumed = 0;
            while consumed < got {
                let space = self.block_size as usize - block_off;
                let n = space.min(got - consumed);
                block_buf[block_off..block_off + n]
                    .copy_from_slice(&scratch[consumed..consumed + n]);
                block_off += n;
                consumed += n;
                bytes_left -= n as u64;
                if block_off == self.block_size as usize {
                    self.write_block(extent_paddr + block_idx, &block_buf)?;
                    block_idx += 1;
                    block_off = 0;
                    block_buf.fill(0);
                }
            }
        }
        // Flush the partial trailing block.
        if block_off > 0 {
            // Zero-pad the rest of the buffer (already zeroed since we
            // call fill(0) each cycle, but be explicit).
            for b in &mut block_buf[block_off..] {
                *b = 0;
            }
            self.write_block(extent_paddr + block_idx, &block_buf)?;
            block_idx += 1;
        }
        // If we still owe more blocks (reader truncated), zero them.
        while block_idx < blocks {
            block_buf.fill(0);
            self.write_block(extent_paddr + block_idx, &block_buf)?;
            block_idx += 1;
        }

        self.add_file_extent(oid, 0, size, extent_paddr)?;
        self.add_inode_record(oid, parent_oid, mode_reg(mode), size, mtime_ns)?;
        self.num_files += 1;
        Ok(oid)
    }

    /// Add an extended attribute under `parent_oid`. The name follows
    /// APFS conventions (caller picks the namespace prefix, e.g.
    /// `"user.note"` or `"com.apple.fs.symlink"`).
    ///
    /// Values up to [`APFS_XATTR_MAX_EMBEDDED_SIZE`] (3804 bytes) are
    /// stored inline in the `j_xattr_val_t`. Larger values would need a
    /// `j_xattr_dstream_t` referencing a separate dstream and are
    /// currently rejected with [`crate::Error::Unsupported`].
    ///
    /// The xattr appears in the fs-tree under
    /// `(parent_oid, APFS_TYPE_XATTR, name)` and is visible via
    /// [`super::Apfs::read_xattrs`].
    pub fn add_xattr(&mut self, parent_oid: u64, name: &str, value: &[u8]) -> Result<()> {
        let (key, val) = build_xattr_record(parent_oid, name, value)?;
        self.records.push(FsRecord { key, val });
        Ok(())
    }

    /// Materialise the on-disk image. After this call the writer is
    /// drained; further `add_*` calls return `Unsupported`.
    pub fn finish(mut self) -> Result<()> {
        if self.finished {
            return Err(crate::Error::Unsupported(
                "apfs writer: finish() called twice".into(),
            ));
        }
        self.finished = true;

        // Sort records into APFS canonical order.
        // A checkpoint keeps the live volume's drec layout; our own
        // format is always plain.
        let hashed = self
            .apsb_template
            .as_ref()
            .and_then(|t| t.get(56..64))
            .is_some_and(|b| {
                super::is_hashed_drec_layout(u64::from_le_bytes(b.try_into().unwrap()))
            });
        ensure_dstream_ids(&mut self.records);
        self.records.sort_by(|a, b| fs_record_cmp(a, b, hashed));
        // Directory inodes carry their child count; the record set is
        // complete here on both the format and the checkpoint path.
        fix_dir_child_counts(&mut self.records);

        let bs = self.block_size as usize;
        let cur_xid = self.xid;
        let format = self.write_label_nxsb;

        // ---- Block addresses (see module-level layout) ----
        // On format (write_label_nxsb = true) we use the fixed layout.
        // On a checkpoint refresh we allocate cont_omap / APSB / vol_omap
        // out of the bump area so the previous checkpoint's blocks remain
        // intact (COW). The spaceman + chkmap aren't consulted by the
        // reader on open, so we keep pointing the new NXSB at the same
        // spaceman_paddr (and chkmap_paddr) — refreshing them would
        // require allocating new xp_desc slots beyond what this v1
        // implementation supports.
        let nxsb_label_paddr: u64 = 0;
        let nxsb_live_paddr: u64 = self.nxsb_paddr;
        // A checkpoint occupies consecutive descriptor slots: its map
        // block(s) then its NXSB. We always emit exactly one map block,
        // in the slot immediately before the superblock.
        let chkmap_paddr: u64 = nxsb_live_paddr - 1;
        let spaceman_paddr: u64 = SPACEMAN_PADDR;
        let reaper_paddr: u64 = SPACEMAN_PADDR + 1;
        let fixed_meta = SPACEMAN_PADDR + self.xp_data_blocks as u64;
        let (cont_omap_paddr, apsb_paddr, vol_omap_paddr) = if format {
            (fixed_meta, fixed_meta + 1, fixed_meta + 2)
        } else {
            (
                self.alloc_block()?,
                self.alloc_block()?,
                self.alloc_block()?,
            )
        };

        // Virtual / ephemeral object ids must be at or above
        // `OID_RESERVED_COUNT` (1024); everything below is reserved for
        // fixed oids like OID_NX_SUPERBLOCK. `fsck_apfs` rejects the
        // container outright otherwise ("nx_reaper_oid (513) is less
        // than minimum OID (1024)"). These mirror the numbering macOS
        // itself hands out.
        let spaceman_vid: u64 = 1024;
        let reaper_vid: u64 = 1025;
        let volume_vid: u64 = 1026;
        let fsroot_vid: u64 = 1027;

        // Blocks the volume owns (`apfs_fs_alloc_count`): its omap,
        // trees and file data. File data was bump-allocated while the
        // records were built, before any metadata.
        let data_blocks = self.next_block - self.bump_block_start;

        // ---- fs-tree (virtual: leaves resolved through the volume omap) ----
        let records = std::mem::take(&mut self.records);
        let fs_tree = self.write_var_tree(&records, FS_TREE, Some(fsroot_vid))?;

        // ---- Extent-reference tree (physical) ----
        // One `j_phys_ext` record per allocated file extent: the kernel
        // consults it to learn who owns a block before it frees or
        // clones it.
        let extent_refs = extent_ref_records(&records, self.block_size);
        let extentref_tree = self.write_var_tree(&extent_refs, EXTENTREF_TREE, None)?;
        self.records = records;

        // ---- Snapshot-metadata tree (physical, empty) ----
        // Only created on format; a checkpoint keeps the live one.
        let snap_meta_tree = if format {
            Some(self.write_var_tree(&[], SNAP_META_TREE, None)?)
        } else {
            None
        };

        // ---- Volume omap ----
        let (vol_omap_root_paddr, vol_omap_nodes) = self.write_omap_tree(&fs_tree.omap)?;
        let vol_omap_phys = build_omap_phys(bs, vol_omap_paddr, vol_omap_root_paddr, cur_xid, 0)?;
        self.write_block(vol_omap_paddr, &vol_omap_phys)?;

        // ---- APSB ----
        let fs_alloc_count = data_blocks
            + 1 // the volume omap header
            + vol_omap_nodes
            + fs_tree.node_count
            + extentref_tree.node_count
            + snap_meta_tree.as_ref().map_or(0, |t| t.node_count);
        let vol = VolumeState {
            vol_omap_paddr,
            fsroot_vid,
            volume_vid,
            extentref_tree_paddr: extentref_tree.root,
            snap_meta_tree_paddr: snap_meta_tree.as_ref().map(|t| t.root),
            fs_alloc_count,
            data_blocks,
        };
        let apsb_block = self.build_apsb(bs, &vol)?;
        self.write_block(apsb_paddr, &apsb_block)?;

        // ---- Container omap: the one volume superblock. Manually
        //      managed, as every container omap is. ----
        let (cont_omap_root_paddr, _) =
            self.write_omap_tree(&[(volume_vid, cur_xid, apsb_paddr)])?;
        let cont_omap_phys = build_omap_phys(
            bs,
            cont_omap_paddr,
            cont_omap_root_paddr,
            cur_xid,
            OMAP_MANUALLY_MANAGED,
        )?;
        self.write_block(cont_omap_paddr, &cont_omap_phys)?;

        // ---- Spaceman (format only) ----
        //
        // The internal pool — the 16-block IP-bitmap ring followed by
        // the pool proper, which holds the CIB and the chunk bitmaps —
        // was reserved by `new` between the fixed metadata and the bump
        // area, so the main bitmap marks the whole used prefix, pool
        // included, in one range.
        //
        // The spaceman + chkmap are only rewritten on format. The reader
        // doesn't consult them during open, so leaving the previous
        // checkpoint's blocks intact keeps the previous checkpoint
        // bootable until the new one is signed.
        if format {
            let ip_bm_base = fixed_meta + 3;
            let ip_base = ip_bm_base + SPACEMAN_IP_BM_TX_MULTIPLIER as u64;
            let layout = SpacemanLayout {
                block_size: bs,
                total_blocks: self.total_blocks,
                xid: cur_xid,
                spaceman_oid: spaceman_vid,
                used_ranges: vec![(0, self.next_block)],
                ip_base,
                ip_bm_base,
                main_fq_node_limit: main_fq_node_limit(self.total_blocks),
            };
            let emitted = spaceman::build_spaceman(&layout)?;
            self.write_block(spaceman_paddr, &emitted.spaceman_block)?;
            self.write_block(emitted.cib_paddr, &emitted.cib_block)?;
            for (paddr, bmap) in emitted
                .bitmap_paddrs
                .iter()
                .zip(emitted.bitmap_blocks.iter())
            {
                self.write_block(*paddr, bmap)?;
            }
            // Live IP-bitmap ring slot (no obj_phys_t header per spec);
            // the free slots are zeroed so stale bytes from a reused
            // image can't masquerade as pool state.
            self.write_block(ip_bm_base, &emitted.ip_bm_block)?;
            let zero = vec![0u8; bs];
            for slot in 1..SPACEMAN_IP_BM_TX_MULTIPLIER as u64 {
                self.write_block(ip_bm_base + slot, &zero)?;
            }
        }

        // ---- Checkpoint map: one entry resolving the spaceman's
        //      ephemeral oid to its physical block. A checkpoint is a
        //      run of map blocks followed by its NXSB, so every
        //      checkpoint — not just the format-time one — needs its
        //      own map block carrying that checkpoint's xid. xp_desc
        //      readers (fsck_apfs included) walk it to find the
        //      spaceman.
        let chkmap = build_chkmap(
            bs,
            chkmap_paddr,
            &[
                (
                    spaceman::OBJECT_TYPE_SPACEMAN | OBJ_EPHEMERAL,
                    spaceman_vid,
                    spaceman_paddr,
                ),
                (
                    OBJECT_TYPE_NX_REAPER | OBJ_EPHEMERAL,
                    reaper_vid,
                    reaper_paddr,
                ),
            ],
            cur_xid,
        )?;
        self.write_block(chkmap_paddr, &chkmap)?;
        // The reaper is an ephemeral object like the spaceman: it lives
        // in the checkpoint data area and is rebuilt with every
        // checkpoint.
        let reaper = build_reaper(bs, reaper_vid, cur_xid)?;
        self.write_block(reaper_paddr, &reaper)?;

        // ---- NXSB ----
        // Live (or new-checkpoint) NXSB goes into the current xp_desc
        // slot. The label copy at block 0 is only refreshed on format
        // — it acts as a stable "where to find the xp_desc area"
        // hint and must NOT be rewritten mid-checkpoint or readers may
        // see a torn label.
        let nxsb = self.build_nxsb(bs, cont_omap_paddr, spaceman_vid, reaper_vid, volume_vid)?;
        self.write_block(nxsb_live_paddr, &nxsb)?;
        if format {
            self.write_block(nxsb_label_paddr, &nxsb)?;
        }
        Ok(())
    }

    /// Emit a variable-size-record B-tree (the fs-tree, the
    /// extent-reference tree or the snapshot-metadata tree) as one leaf
    /// or as leaves under a single internal root.
    ///
    /// With `virtual_root = Some(vid)` the tree is virtual: the root is
    /// object `vid`, non-root leaves get oids from
    /// [`FS_LEAF_VID_BASE`], internal-node values are those oids, and
    /// the returned `omap` lists the `(oid, xid, paddr)` mappings the
    /// volume omap must carry. Otherwise the tree is physical: every
    /// node's oid is its block address and so is every child pointer.
    fn write_var_tree(
        &mut self,
        records: &[FsRecord],
        kind: TreeKind,
        virtual_root: Option<u64>,
    ) -> Result<TreeOut> {
        let bs = self.block_size as usize;
        let xid = self.xid;
        let leaves = pack_records_into_leaves(records, leaf_payload_capacity(bs))?;
        let paddrs: Vec<u64> = (0..leaves.len())
            .map(|_| self.alloc_block())
            .collect::<Result<Vec<_>>>()?;
        let multi = leaves.len() > 1;
        let node_count = leaves.len() as u64 + u64::from(multi);
        let key_count = records.len() as u64;
        let mut omap = Vec::new();
        let leaf_oid = |i: usize| match virtual_root {
            Some(vid) if !multi => vid,
            Some(_) => FS_LEAF_VID_BASE + i as u64,
            None => paddrs[i],
        };
        let longest_key = records.iter().map(|r| r.key.len()).max().unwrap_or(0) as u32;
        let longest_val = records.iter().map(|r| r.val.len()).max().unwrap_or(0) as u32;
        for (i, leaf) in leaves.iter().enumerate() {
            let oid = leaf_oid(i);
            if virtual_root.is_some() {
                omap.push((oid, xid, paddrs[i]));
            }
            let block = build_fs_leaf(
                leaf,
                bs,
                oid,
                !multi,
                xid,
                key_count,
                node_count,
                kind,
                virtual_root.is_none(),
            )?;
            self.write_block(paddrs[i], &block)?;
        }
        if !multi {
            return Ok(TreeOut {
                root: paddrs[0],
                node_count,
                omap,
            });
        }
        let root_paddr = self.alloc_block()?;
        let root_oid = virtual_root.unwrap_or(root_paddr);
        if virtual_root.is_some() {
            omap.push((root_oid, xid, root_paddr));
            omap.sort_by_key(|e| e.0);
        }
        let sep_entries: Vec<(Vec<u8>, u64)> = leaves
            .iter()
            .enumerate()
            .map(|(i, leaf)| (leaf[0].key.clone(), leaf_oid(i)))
            .collect();
        let block = build_fs_internal_root(
            &sep_entries,
            bs,
            root_oid,
            xid,
            longest_key,
            longest_val,
            key_count,
            node_count,
            kind,
            virtual_root.is_none(),
        )?;
        self.write_block(root_paddr, &block)?;
        Ok(TreeOut {
            root: root_paddr,
            node_count,
            omap,
        })
    }

    // ---- internal helpers ----

    /// Descriptor slot holding this checkpoint's map block: the one
    /// immediately before its superblock.
    fn chkmap_paddr(&self) -> u64 {
        self.nxsb_paddr - 1
    }

    fn alloc_oid(&mut self) -> u64 {
        let o = self.next_oid;
        self.next_oid = self.next_oid.checked_add(1).unwrap_or(o);
        o
    }

    fn bytes_to_blocks(&self, n: u64) -> u64 {
        let bs = self.block_size as u64;
        n.div_ceil(bs).max(1)
    }

    /// Bump-allocate one block from the metadata/data area. Errors if
    /// the image would run out of room.
    fn alloc_block(&mut self) -> Result<u64> {
        if self.next_block >= self.total_blocks {
            return Err(crate::Error::InvalidArgument(format!(
                "apfs writer: image full at {} blocks",
                self.total_blocks
            )));
        }
        let p = self.next_block;
        self.next_block += 1;
        Ok(p)
    }

    fn allocate_extent_for_size(&mut self, size: u64) -> Result<u64> {
        if size == 0 {
            return Err(crate::Error::InvalidArgument(
                "apfs writer: cannot allocate a zero-length extent".into(),
            ));
        }
        let blocks = self.bytes_to_blocks(size);
        let start = self.next_block;
        let end = start
            .checked_add(blocks)
            .ok_or_else(|| crate::Error::InvalidArgument("apfs writer: extent oob".into()))?;
        if end > self.total_blocks {
            return Err(crate::Error::InvalidArgument(format!(
                "apfs writer: extent of {blocks} blocks past end of image"
            )));
        }
        self.next_block = end;
        Ok(start)
    }

    fn write_block(&mut self, paddr: u64, buf: &[u8]) -> Result<()> {
        let off = paddr.saturating_mul(self.block_size as u64);
        self.dev.write_at(off, buf)
    }

    fn add_drec(&mut self, parent_oid: u64, name: &str, target_oid: u64, dtype: u16) -> Result<()> {
        // Plain drec key — `ApfsWriter::new` always formats without
        // APFS_INCOMPAT_NORMALIZATION_INSENSITIVE, so the single-pass
        // writer's drecs stay plain-key. The Write-state mutators
        // (Apfs::create_*_at, rename, link) pass the volume's actual
        // layout instead.
        let (key, val) = build_drec_record(
            parent_oid,
            name,
            target_oid,
            dtype,
            super::fstree::DrecKeyLayout::Plain,
            false,
        )?;
        self.records.push(FsRecord { key, val });
        Ok(())
    }

    fn add_inode_record(
        &mut self,
        oid: u64,
        parent_oid: u64,
        mode: u16,
        dstream_size: u64,
        mtime_ns: u64,
    ) -> Result<()> {
        let (key, val) = build_inode_record(
            oid,
            parent_oid,
            mode,
            dstream_size,
            self.block_size,
            mtime_ns,
        );
        self.records.push(FsRecord { key, val });
        Ok(())
    }

    fn add_file_extent(
        &mut self,
        dstream_oid: u64,
        logical_addr: u64,
        length: u64,
        phys_block: u64,
    ) -> Result<()> {
        let pair = build_file_extent_records(
            dstream_oid,
            logical_addr,
            length,
            phys_block,
            self.block_size,
        );
        for (key, val) in pair {
            self.records.push(FsRecord { key, val });
        }
        Ok(())
    }

    /// Emit an omap as one or more leaf blocks plus, if necessary, a
    /// single internal-root block. Returns the paddr of the tree's
    /// root (leaf for a single-leaf tree, internal node otherwise) and
    /// the number of nodes written.
    fn write_omap_tree(&mut self, entries: &[(u64, u64, u64)]) -> Result<(u64, u64)> {
        let bs = self.block_size as usize;
        let xid = self.xid;
        let leaves = pack_omap_into_leaves(entries, omap_leaf_capacity(bs))?;
        if leaves.len() == 1 {
            // Single leaf: it's the root and carries the trailing
            // btree_info_t.
            let paddr = self.alloc_block()?;
            let block =
                build_omap_leaf_node(bs, paddr, &leaves[0], true, xid, entries.len() as u64, 1)?;
            self.write_block(paddr, &block)?;
            return Ok((paddr, 1));
        }
        // Multi-leaf: emit each leaf at its own paddr, then a single
        // internal root with 16-byte keys and 8-byte child paddrs.
        let mut leaf_paddrs: Vec<u64> = Vec::with_capacity(leaves.len());
        let mut sep_entries: Vec<((u64, u64), u64)> = Vec::with_capacity(leaves.len());
        for chunk in &leaves {
            let paddr = self.alloc_block()?;
            let block = build_omap_leaf_node(bs, paddr, chunk, false, xid, 0, 0)?;
            self.write_block(paddr, &block)?;
            leaf_paddrs.push(paddr);
            sep_entries.push(((chunk[0].0, chunk[0].1), paddr));
        }
        let root_paddr = self.alloc_block()?;
        let root_block = build_omap_internal_root(
            bs,
            root_paddr,
            &sep_entries,
            xid,
            entries.len() as u64,
            leaves.len() as u64 + 1,
        )?;
        self.write_block(root_paddr, &root_block)?;
        Ok((root_paddr, leaves.len() as u64 + 1))
    }

    /// Build the volume superblock.
    ///
    /// On a checkpoint (`apsb_template` is `Some`) the live volume
    /// superblock is used as the base and only the fields this
    /// checkpoint actually changes are patched. Building from a fixed
    /// template instead would zero `apfs_features`,
    /// `apfs_incompatible_features` (which decides whether drec keys
    /// are hashed — so the very next open would misparse every
    /// directory entry), `apfs_snap_meta_tree_oid`, `apfs_role` and
    /// the encryption state.
    fn build_apsb(&self, bs: usize, vol: &VolumeState) -> Result<Vec<u8>> {
        let mut buf = match &self.apsb_template {
            Some(t) if t.len() == bs => t.clone(),
            _ => self.fresh_apsb(bs),
        };
        // obj_phys. The volume superblock is a *virtual* object: its
        // `o_oid` is the oid the container omap maps to this block, not
        // the block address. Stamping the paddr here is what made
        // `fsck_apfs` report "o_oid invalid" and hdiutil refuse to
        // mount ("no mountable file systems").
        buf[8..16].copy_from_slice(&vol.volume_vid.to_le_bytes()); // oid
        buf[16..24].copy_from_slice(&self.xid.to_le_bytes());
        // o_type = OBJECT_TYPE_FS | OBJ_VIRTUAL (0).
        buf[24..28].copy_from_slice(&OBJECT_TYPE_FS.to_le_bytes());
        buf[28..32].copy_from_slice(&0u32.to_le_bytes()); // o_subtype

        buf[88..96].copy_from_slice(&vol.fs_alloc_count.to_le_bytes()); // apfs_fs_alloc_count
        // Tree types: the fs-tree is virtual, the extent-reference and
        // snapshot-metadata trees are physical.
        buf[116..120].copy_from_slice(&OBJECT_TYPE_BTREE.to_le_bytes());
        buf[120..124].copy_from_slice(&(OBJECT_TYPE_BTREE | OBJ_PHYSICAL).to_le_bytes());
        buf[124..128].copy_from_slice(&(OBJECT_TYPE_BTREE | OBJ_PHYSICAL).to_le_bytes());
        buf[128..136].copy_from_slice(&vol.vol_omap_paddr.to_le_bytes()); // omap_oid
        buf[136..144].copy_from_slice(&vol.fsroot_vid.to_le_bytes()); // root_tree_oid
        buf[144..152].copy_from_slice(&vol.extentref_tree_paddr.to_le_bytes());
        if let Some(p) = vol.snap_meta_tree_paddr {
            buf[152..160].copy_from_slice(&p.to_le_bytes());
        }
        buf[176..184].copy_from_slice(&self.next_oid.to_le_bytes()); // next_obj_id
        buf[184..192].copy_from_slice(&self.num_files.to_le_bytes());
        buf[192..200].copy_from_slice(&self.num_directories.to_le_bytes());
        buf[200..208].copy_from_slice(&self.num_symlinks.to_le_bytes());
        if self.apsb_template.is_none() {
            // apfs_total_blocks_alloced: the file data written so far.
            buf[224..232].copy_from_slice(&vol.data_blocks.to_le_bytes());
        }
        buf[240..256].copy_from_slice(&self.volume_uuid);
        // volname at offset 704 (256 bytes)
        let name_bytes = self.volume_name.as_bytes();
        let n = name_bytes.len().min(255);
        buf[704..704 + 256].fill(0);
        buf[704..704 + n].copy_from_slice(&name_bytes[..n]);

        // Final checksum.
        sign_block(&mut buf);
        Ok(buf)
    }

    /// The format-time volume superblock fields that no checkpoint
    /// changes, laid out the way `newfs_apfs` writes them.
    fn fresh_apsb(&self, bs: usize) -> Vec<u8> {
        let mut fresh = vec![0u8; bs];
        fresh[32..36].copy_from_slice(&APFS_MAGIC.to_le_bytes());
        fresh[36..40].copy_from_slice(&0u32.to_le_bytes()); // fs_index
        // features / ro_compat / incompat: 0 (plain drec layout,
        // case- and normalization-sensitive, no sealing / encryption).
        //
        // apfs_meta_crypto (wrapped_meta_crypto_state_t at 96): the
        // version APFS expects even on an unencrypted volume —
        // major 5 (APFS_WMCS_MAJOR_VERSION), minor 0, persistent
        // class F (PROTECTION_CLASS_F = 6), key revision 1.
        fresh[96..98].copy_from_slice(&5u16.to_le_bytes());
        fresh[104..108].copy_from_slice(&6u32.to_le_bytes());
        fresh[112..114].copy_from_slice(&1u16.to_le_bytes());
        const APFS_FS_UNENCRYPTED: u64 = 0x0000_0001;
        fresh[264..272].copy_from_slice(&APFS_FS_UNENCRYPTED.to_le_bytes());
        // apfs_formatted_by (apfs_modified_by_t at 272): id[32],
        // timestamp, last_xid.
        let id = concat!("fstool (", env!("CARGO_PKG_VERSION"), ")").as_bytes();
        let n = id.len().min(31);
        fresh[272..272 + n].copy_from_slice(&id[..n]);
        fresh[312..320].copy_from_slice(&self.xid.to_le_bytes());
        // apfs_next_doc_id: document ids start after the two reserved.
        fresh[960..964].copy_from_slice(&3u32.to_le_bytes());
        // apfs_fext_tree_type / reserved_type: physical B-trees, as
        // newfs_apfs records them even though no fext tree exists.
        if bs >= 1048 {
            fresh[1040..1044].copy_from_slice(&(OBJECT_TYPE_BTREE | OBJ_PHYSICAL).to_le_bytes());
            fresh[1044..1048].copy_from_slice(&(OBJECT_TYPE_BTREE | OBJ_PHYSICAL).to_le_bytes());
        }
        fresh
    }

    /// Build the container superblock (the live checkpoint's copy and,
    /// on format, the block-0 label — they are identical).
    fn build_nxsb(
        &self,
        bs: usize,
        cont_omap_paddr: u64,
        spaceman_vid: u64,
        reaper_vid: u64,
        volume_vid: u64,
    ) -> Result<Vec<u8>> {
        let mut buf = match &self.nxsb_template {
            Some(t) if t.len() == bs => t.clone(),
            _ => vec![0u8; bs],
        };
        // obj_phys. Every copy of the container superblock — the label
        // at block 0 and every checkpoint-descriptor slot — carries
        // `o_oid = OID_NX_SUPERBLOCK` (1), not its own block address:
        // it's the one ephemeral object with a fixed, reserved oid.
        // Writing the paddr instead made `fsck_apfs` reject every
        // checkpoint ("nx_sb->nx_o.o_oid != OID_NX_SUPERBLOCK") and
        // hdiutil refuse to mount the image at all.
        buf[8..16].copy_from_slice(&OID_NX_SUPERBLOCK.to_le_bytes());
        buf[16..24].copy_from_slice(&self.xid.to_le_bytes());
        buf[24..28].copy_from_slice(&(OBJECT_TYPE_NX_SUPERBLOCK | OBJ_EPHEMERAL).to_le_bytes());

        buf[32..36].copy_from_slice(&NX_MAGIC.to_le_bytes());
        buf[36..40].copy_from_slice(&self.block_size.to_le_bytes());
        buf[40..48].copy_from_slice(&self.total_blocks.to_le_bytes());
        // features / ro_compat come from the template on a checkpoint
        // (zero on format — we ship a vanilla container). The
        // incompatible features must carry NX_INCOMPAT_VERSION2: the
        // macOS kernel only mounts version-2 containers, and a
        // container without the bit is attached but never opened (the
        // APFS container scheme shows up with no physical store and
        // `diskutil` reports error -69808), while `fsck_apfs` checks it
        // without complaint.
        let incompat = u64::from_le_bytes(buf[64..72].try_into().unwrap()) | NX_INCOMPAT_VERSION2;
        buf[64..72].copy_from_slice(&incompat.to_le_bytes());
        buf[72..88].copy_from_slice(&self.container_uuid);
        // nx_next_oid must be past every virtual/ephemeral oid we
        // hand out, and fs-tree leaves are numbered from
        // FS_LEAF_VID_BASE upwards.
        buf[88..96].copy_from_slice(&(FS_LEAF_VID_BASE + 0x1_0000).to_le_bytes()); // next_oid
        buf[96..104].copy_from_slice(&(self.xid + 1).to_le_bytes()); // next_xid
        // xp_desc area: XP_DESC_BLOCKS blocks (chkmap stub at block 1 +
        // the live NXSB at block 2 + XP_DESC_BLOCKS-2 spare slots for
        // future checkpoint rotation via Apfs::open_writable).
        // xp_desc_base = 1; reader scans this range looking for the
        // largest-xid NXSB.
        buf[104..108].copy_from_slice(&XP_DESC_BLOCKS.to_le_bytes()); // xp_desc_blocks
        buf[108..112].copy_from_slice(&self.xp_data_blocks.to_le_bytes()); // xp_data_blocks
        buf[112..120].copy_from_slice(&CHKMAP_PADDR.to_le_bytes()); // xp_desc_base
        buf[120..128].copy_from_slice(&SPACEMAN_PADDR.to_le_bytes()); // xp_data_base = spaceman_paddr
        // Checkpoint geometry. `xp_desc_index` is where this checkpoint
        // starts inside the descriptor ring and `xp_desc_len` how many
        // slots it spans — one map block plus this superblock, so
        // always 2. `fsck_apfs` rejects anything smaller
        // ("nx_xp_desc_len (0) is less than 2"), which is what the
        // label copy used to claim because its own block number was
        // being used as the length.
        let desc_index = (self.chkmap_paddr().saturating_sub(CHKMAP_PADDR)) as u32;
        let desc_len = CHECKPOINT_DESC_SLOTS;
        let desc_next = (desc_index + desc_len) % XP_DESC_BLOCKS;
        buf[128..132].copy_from_slice(&desc_next.to_le_bytes()); // xp_desc_next
        buf[132..136].copy_from_slice(&XP_DATA_USED.to_le_bytes()); // xp_data_next
        buf[136..140].copy_from_slice(&desc_index.to_le_bytes()); // xp_desc_index
        buf[140..144].copy_from_slice(&desc_len.to_le_bytes()); // xp_desc_len
        buf[144..148].copy_from_slice(&0u32.to_le_bytes()); // xp_data_index
        buf[148..152].copy_from_slice(&XP_DATA_USED.to_le_bytes()); // xp_data_len
        buf[152..160].copy_from_slice(&spaceman_vid.to_le_bytes());
        buf[160..168].copy_from_slice(&cont_omap_paddr.to_le_bytes()); // omap_oid
        buf[168..176].copy_from_slice(&reaper_vid.to_le_bytes()); // reaper_oid
        buf[176..180].copy_from_slice(&0u32.to_le_bytes()); // test_type
        // nx_max_file_systems: one volume per 512 MiB of container,
        // rounded up, at most NX_MAX_FILE_SYSTEMS — the figure macOS
        // computes and checks.
        let bytes = self.total_blocks * self.block_size as u64;
        let max_fs = bytes
            .div_ceil(512 << 20)
            .clamp(1, NX_MAX_FILE_SYSTEMS as u64) as u32;
        buf[180..184].copy_from_slice(&max_fs.to_le_bytes());
        // fs_oid[volume_index] = volume_vid. `open_writable` refuses
        // multi-volume containers, so the remaining slots are already
        // zero (format) or already correct (checkpoint template).
        let fs_oid_off = 184 + self.volume_index * 8;
        if fs_oid_off + 8 <= bs {
            buf[fs_oid_off..fs_oid_off + 8].copy_from_slice(&volume_vid.to_le_bytes());
        }

        // nx_ephemeral_info[0]: version 1, 4 ephemeral structures per
        // volume, and the minimum block count newfs_apfs derives from
        // the main free queue's node limit (capped at 8). Leaving it
        // zero makes `fsck_apfs` warn about every field of it.
        if bs >= 1344 {
            let min_blocks = u64::from(main_fq_node_limit(self.total_blocks).min(8));
            let info = NX_EPHEMERAL_INFO_0 | (min_blocks << 32);
            buf[1312..1320].copy_from_slice(&info.to_le_bytes());
        }

        // Silence unused-variable warning when the writer ends up not
        // needing to walk the bump pointer afterwards.
        let _ = self.bump_block_start;
        sign_block(&mut buf);
        Ok(buf)
    }
}

// ---- block builders (free fns) ----

/// Compute the Fletcher-64 checksum over the rest of `buf` and write it
/// into the first 8 bytes.
fn sign_block(buf: &mut [u8]) {
    let cksum = fletcher64(buf);
    buf[0..8].copy_from_slice(&cksum.to_le_bytes());
}

/// Build an omap_phys_t (header) block. `paddr` is the block this
/// header lives at; `tree_paddr` is the physical block of the tree's
/// root.
fn build_omap_phys(
    bs: usize,
    paddr: u64,
    tree_paddr: u64,
    xid: u64,
    flags: u32,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; bs];
    buf[8..16].copy_from_slice(&paddr.to_le_bytes()); // oid
    buf[16..24].copy_from_slice(&xid.to_le_bytes()); // xid
    buf[24..28].copy_from_slice(&(OBJECT_TYPE_OMAP | OBJ_PHYSICAL).to_le_bytes());
    buf[32..36].copy_from_slice(&flags.to_le_bytes()); // om_flags
    // om_snap_count stays 0. Both tree types are physical B-trees, the
    // snapshot tree's included even though there is none yet.
    let tree_type = OBJECT_TYPE_BTREE | OBJ_PHYSICAL;
    buf[40..44].copy_from_slice(&tree_type.to_le_bytes()); // om_tree_type
    buf[44..48].copy_from_slice(&tree_type.to_le_bytes()); // om_snapshot_tree_type
    buf[48..56].copy_from_slice(&tree_paddr.to_le_bytes());
    // snapshot_tree_oid stays 0.
    sign_block(&mut buf);
    Ok(buf)
}

/// Round a node's table-of-contents length up the way APFS does: the
/// ToC area is over-allocated and 8-byte aligned, and `fsck_apfs`
/// rejects a node whose `btn_table_space.len` isn't ("invalid
/// btn_table_space (0, 4)").
fn toc_space(raw_len: usize) -> usize {
    raw_len.div_ceil(8) * 8
}

/// ToC length for a variable-KV node holding `n` entries: the table
/// grows in steps of `BTREE_TOC_ENTRY_INCREMENT` (8) `kvloc_t`s, so an
/// empty or small node still reserves 8 — what macOS writes.
fn toc_space_var(n: usize) -> usize {
    n.max(1).div_ceil(BTREE_TOC_ENTRY_INCREMENT) * BTREE_TOC_ENTRY_INCREMENT * 8
}

/// `BTREE_TOC_ENTRY_INCREMENT`.
const BTREE_TOC_ENTRY_INCREMENT: usize = 8;

/// ToC length for a *fixed*-KV node. A fixed-layout node reserves a
/// table entry for every record the node could ever hold, not just the
/// ones it holds now — `fsck_apfs` recomputes that capacity and
/// rejects anything smaller ("invalid btn_table_space (0, 8), given
/// btn_flags (0x7)"). One entry costs 4 ToC bytes plus the key and
/// value.
fn toc_space_fixed(bs: usize, is_root: bool, key_size: usize, val_size: usize) -> usize {
    let usable = bs - 56 - if is_root { BTREE_INFO_SIZE } else { 0 };
    let capacity = usable / (4 + key_size + val_size);
    toc_space(capacity * 4)
}

/// Fill in `btn_free_space`, `btn_key_free_list` and `btn_val_free_list`
/// for a freshly built node. `used_keys` / `used_vals` are byte counts;
/// the free-space extent is what's left between them. A newly built
/// node has no freed entries, so both free lists carry APFS's "empty"
/// marker (`BTOFF_INVALID`).
fn write_node_free_space(
    block: &mut [u8],
    keys_start: usize,
    vals_end: usize,
    used_keys: usize,
    used_vals: usize,
) {
    let span = vals_end.saturating_sub(keys_start);
    let free_len = span.saturating_sub(used_keys + used_vals);
    block[44..46].copy_from_slice(&(used_keys as u16).to_le_bytes());
    block[46..48].copy_from_slice(&(free_len as u16).to_le_bytes());
    block[48..50].copy_from_slice(&BTOFF_INVALID.to_le_bytes());
    block[50..52].copy_from_slice(&0u16.to_le_bytes());
    block[52..54].copy_from_slice(&BTOFF_INVALID.to_le_bytes());
    block[54..56].copy_from_slice(&0u16.to_le_bytes());
}

/// `btree_info_t.bt_fixed.bt_flags` for an omap: the tree stores
/// physical block addresses and is built by sequential insert.
const BTREE_FLAGS_OMAP: u32 = 0x0000_0012;
/// …and for an fs-tree: variable-size, unaligned keys and values,
/// built by sequential insert. Both match what macOS writes.
const BTREE_FLAGS_FSTREE: u32 = 0x0000_0042;
/// …and for the volume's physical trees (extent references, snapshot
/// metadata): the fs-tree flags plus `BTREE_PHYSICAL`.
const BTREE_FLAGS_PHYS_VAR: u32 = 0x0000_0052;

/// `OBJECT_TYPE_BLOCKREFTREE` — the extent-reference tree.
const OBJECT_TYPE_BLOCKREFTREE: u32 = 0x0000_000f;
/// `OBJECT_TYPE_SNAPMETATREE` — the snapshot-metadata tree.
const OBJECT_TYPE_SNAPMETATREE: u32 = 0x0000_0010;

/// What a variable-KV volume tree holds: its node subtype and its
/// `btree_info_t.bt_flags`.
#[derive(Clone, Copy)]
struct TreeKind {
    subtype: u32,
    info_flags: u32,
}

const FS_TREE: TreeKind = TreeKind {
    subtype: OBJECT_TYPE_FSTREE,
    info_flags: BTREE_FLAGS_FSTREE,
};
const EXTENTREF_TREE: TreeKind = TreeKind {
    subtype: OBJECT_TYPE_BLOCKREFTREE,
    info_flags: BTREE_FLAGS_PHYS_VAR,
};
const SNAP_META_TREE: TreeKind = TreeKind {
    subtype: OBJECT_TYPE_SNAPMETATREE,
    info_flags: BTREE_FLAGS_PHYS_VAR,
};

/// Where [`ApfsWriter::write_var_tree`] put a tree.
struct TreeOut {
    /// Block address of the root node.
    root: u64,
    /// Nodes written.
    node_count: u64,
    /// `(oid, xid, paddr)` volume-omap entries (virtual trees only),
    /// sorted by oid.
    omap: Vec<(u64, u64, u64)>,
}

/// Per-checkpoint volume facts [`ApfsWriter::build_apsb`] stamps.
struct VolumeState {
    vol_omap_paddr: u64,
    fsroot_vid: u64,
    volume_vid: u64,
    extentref_tree_paddr: u64,
    /// `None` keeps the template's snapshot-metadata tree.
    snap_meta_tree_paddr: Option<u64>,
    fs_alloc_count: u64,
    data_blocks: u64,
}

/// `APFS_TYPE_EXTENT` — a `j_phys_ext` record in the extent-reference
/// tree.
const APFS_TYPE_EXTENT: u8 = 2;
/// `PEXT_KIND_NEW` in the top bits of `j_phys_ext_val_t.len_and_kind`.
const PEXT_KIND_NEW: u64 = 1;

/// Build the extent-reference tree's records — one `j_phys_ext` per
/// allocated file extent, keyed by its first block, owned by the data
/// stream and referenced once — from the fs-tree's FILE_EXTENT
/// records. Sorted by block address.
fn extent_ref_records(fs_records: &[FsRecord], block_size: u32) -> Vec<FsRecord> {
    let mut out: Vec<(u64, FsRecord)> = Vec::new();
    for r in fs_records {
        if r.key.len() < 16 || r.val.len() < 16 {
            continue;
        }
        let hdr = u64::from_le_bytes(r.key[0..8].try_into().unwrap());
        if (hdr >> OBJ_TYPE_SHIFT) as u8 != APFS_TYPE_FILE_EXTENT {
            continue;
        }
        let len = u64::from_le_bytes(r.val[0..8].try_into().unwrap()) & ((1 << 56) - 1);
        let paddr = u64::from_le_bytes(r.val[8..16].try_into().unwrap());
        let blocks = len.div_ceil(block_size as u64);
        if paddr == 0 || blocks == 0 {
            continue; // a hole owns no blocks
        }
        let mut key = vec![0u8; 8];
        let khdr = ((APFS_TYPE_EXTENT as u64) << OBJ_TYPE_SHIFT) | (paddr & OBJ_ID_MASK);
        key.copy_from_slice(&khdr.to_le_bytes());
        let mut val = vec![0u8; 20];
        val[0..8].copy_from_slice(&(blocks | (PEXT_KIND_NEW << 60)).to_le_bytes());
        val[8..16].copy_from_slice(&(hdr & OBJ_ID_MASK).to_le_bytes()); // owning_obj_id
        val[16..20].copy_from_slice(&1i32.to_le_bytes()); // refcnt
        out.push((paddr, FsRecord { key, val }));
    }
    out.sort_by_key(|(p, _)| *p);
    out.dedup_by_key(|(p, _)| *p);
    out.into_iter().map(|(_, r)| r).collect()
}

/// Give every inode that carries a data stream (a DSTREAM xfield) the
/// `j_dstream_id` record that keeps the stream alive. Writers only
/// emit one alongside a file extent, so an empty regular file would
/// otherwise reference a stream that doesn't exist ("dstream (id N)
/// does not have an associated dstream id object").
fn ensure_dstream_ids(records: &mut Vec<FsRecord>) {
    let mut have = std::collections::HashSet::new();
    let mut need = Vec::new();
    for r in records.iter() {
        let hdr = u64::from_le_bytes(r.key[0..8].try_into().unwrap());
        match (hdr >> OBJ_TYPE_SHIFT) as u8 {
            APFS_TYPE_DSTREAM_ID => {
                have.insert(hdr & OBJ_ID_MASK);
            }
            APFS_TYPE_INODE if inode_has_dstream(&r.val) => {
                need.push(u64::from_le_bytes(r.val[8..16].try_into().unwrap()));
            }
            _ => {}
        }
    }
    for oid in need {
        if have.insert(oid) {
            let hdr = ((APFS_TYPE_DSTREAM_ID as u64) << OBJ_TYPE_SHIFT) | (oid & OBJ_ID_MASK);
            records.push(FsRecord {
                key: hdr.to_le_bytes().to_vec(),
                val: 1u32.to_le_bytes().to_vec(),
            });
        }
    }
}

/// Whether an inode value's xfields include `INO_EXT_TYPE_DSTREAM`.
fn inode_has_dstream(val: &[u8]) -> bool {
    let x = match val.get(J_INODE_VAL_FIXED_SIZE..) {
        Some(x) if x.len() >= 4 => x,
        _ => return false,
    };
    let n = u16::from_le_bytes([x[0], x[1]]) as usize;
    (0..n).any(|i| x.get(4 + i * 4) == Some(&INO_EXT_TYPE_DSTREAM))
}

/// Set every directory inode's `nchildren` to the number of directory
/// entries filed under it. `records` must be the complete, sorted
/// record set.
fn fix_dir_child_counts(records: &mut [FsRecord]) {
    let mut counts: std::collections::HashMap<u64, i32> = std::collections::HashMap::new();
    for r in records.iter() {
        let hdr = u64::from_le_bytes(r.key[0..8].try_into().unwrap());
        if (hdr >> OBJ_TYPE_SHIFT) as u8 == APFS_TYPE_DIR_REC {
            *counts.entry(hdr & OBJ_ID_MASK).or_default() += 1;
        }
    }
    for r in records.iter_mut() {
        let hdr = u64::from_le_bytes(r.key[0..8].try_into().unwrap());
        if (hdr >> OBJ_TYPE_SHIFT) as u8 != APFS_TYPE_INODE || r.val.len() < 84 {
            continue;
        }
        let mode = u16::from_le_bytes(r.val[80..82].try_into().unwrap());
        if mode & 0o170_000 != 0o040_000 {
            continue;
        }
        let n = counts.get(&(hdr & OBJ_ID_MASK)).copied().unwrap_or(0);
        r.val[56..60].copy_from_slice(&n.to_le_bytes());
    }
}

/// Fill the trailing `btree_info_t` of a root node. `fsck_apfs`
/// validates every field of it against the tree it actually finds, and
/// a zeroed one fails immediately ("invalid btn_btree.bt_fixed.bt_flags
/// (0x0)").
#[allow(clippy::too_many_arguments)]
fn write_btree_info(
    block: &mut [u8],
    bs: usize,
    flags: u32,
    key_size: u32,
    val_size: u32,
    longest_key: u32,
    longest_val: u32,
    key_count: u64,
    node_count: u64,
) {
    let o = bs - BTREE_INFO_SIZE;
    block[o..o + 4].copy_from_slice(&flags.to_le_bytes()); // bt_flags
    block[o + 4..o + 8].copy_from_slice(&(bs as u32).to_le_bytes()); // bt_node_size
    block[o + 8..o + 12].copy_from_slice(&key_size.to_le_bytes());
    block[o + 12..o + 16].copy_from_slice(&val_size.to_le_bytes());
    block[o + 16..o + 20].copy_from_slice(&longest_key.to_le_bytes());
    block[o + 20..o + 24].copy_from_slice(&longest_val.to_le_bytes());
    block[o + 24..o + 32].copy_from_slice(&key_count.to_le_bytes());
    block[o + 32..o + 40].copy_from_slice(&node_count.to_le_bytes());
}

/// Effective payload capacity for an omap leaf node (root or otherwise).
/// `key_size + val_size = 32`; ToC entries cost 4 bytes each. We
/// conservatively use the root layout (subtract `btree_info_t`) for both
/// root and non-root leaves so the per-leaf record count stays
/// consistent.
fn omap_leaf_capacity(bs: usize) -> usize {
    // The packing math: each entry adds 4 (ToC) + 16 (key) + 16 (val) = 36
    // bytes. Available = bs - obj_header(56) - btree_info_t(40) for the
    // root case. For non-root leaves we'd have 40 more bytes, but we use
    // the conservative figure so the splitter doesn't need to know which
    // leaf is the root.
    bs - 56 - BTREE_INFO_SIZE
}

/// Pack an omap entry list (already sorted by `(oid, xid)`) into one or
/// more leaf groups. Each group fits inside `cap` bytes when accounting
/// for the 4-byte ToC entry + 16+16 byte fixed-KV payload.
fn pack_omap_into_leaves(
    entries: &[(u64, u64, u64)],
    cap: usize,
) -> Result<Vec<Vec<(u64, u64, u64)>>> {
    let per = 4 + 16 + 16;
    let max_per_leaf = cap / per;
    if max_per_leaf == 0 {
        return Err(crate::Error::Unsupported(
            "apfs writer: block too small to fit any omap entry".into(),
        ));
    }
    if entries.is_empty() {
        return Ok(vec![Vec::new()]);
    }
    // Verify ascending order so the split is meaningful.
    let mut out: Vec<Vec<(u64, u64, u64)>> = Vec::new();
    for chunk in entries.chunks(max_per_leaf) {
        out.push(chunk.to_vec());
    }
    Ok(out)
}

/// Build an omap leaf node (fixed-KV 16/16). When `is_root` is true the
/// node carries `BTNODE_ROOT` and a trailing `btree_info_t`.
fn build_omap_leaf_node(
    bs: usize,
    paddr: u64,
    entries: &[(u64, u64, u64)],
    is_root: bool,
    xid: u64,
    tree_key_count: u64,
    tree_node_count: u64,
) -> Result<Vec<u8>> {
    let mut block = vec![0u8; bs];
    let obj_type = if is_root {
        OBJECT_TYPE_BTREE | OBJ_PHYSICAL
    } else {
        OBJECT_TYPE_BTREE_NODE | OBJ_PHYSICAL
    };
    // A physical object's `o_oid` is the block it lives on, and the
    // subtype says what the tree holds. Leaving both zero is what made
    // `fsck_apfs` report "om: bt: invalid o_oid (0x0)".
    block[8..16].copy_from_slice(&paddr.to_le_bytes());
    block[16..24].copy_from_slice(&xid.to_le_bytes());
    block[24..28].copy_from_slice(&obj_type.to_le_bytes());
    block[28..32].copy_from_slice(&OBJECT_TYPE_OMAP.to_le_bytes());

    let mut flags = BTNODE_LEAF | BTNODE_FIXED_KV_SIZE;
    if is_root {
        flags |= BTNODE_ROOT;
    }
    block[32..34].copy_from_slice(&flags.to_le_bytes());
    block[34..36].copy_from_slice(&0u16.to_le_bytes()); // level
    block[36..40].copy_from_slice(&(entries.len() as u32).to_le_bytes());

    let toc_len = toc_space_fixed(bs, is_root, 16, 16);
    block[40..42].copy_from_slice(&0u16.to_le_bytes());
    block[42..44].copy_from_slice(&(toc_len as u16).to_le_bytes());

    let toc_base = 56;
    let keys_start = toc_base + toc_len;
    let vals_end = if is_root { bs - BTREE_INFO_SIZE } else { bs };
    write_node_free_space(
        &mut block,
        keys_start,
        vals_end,
        entries.len() * 16,
        entries.len() * 16,
    );
    if entries.len() * 32 + toc_len + 56 > vals_end {
        return Err(crate::Error::Unsupported(
            "apfs writer: omap leaf overflowed single block".into(),
        ));
    }
    for (i, &(oid, xid, paddr)) in entries.iter().enumerate() {
        let k_off = (i * 16) as u16;
        let v_off = ((i + 1) * 16) as u16;
        block[toc_base + i * 4..toc_base + i * 4 + 2].copy_from_slice(&k_off.to_le_bytes());
        block[toc_base + i * 4 + 2..toc_base + i * 4 + 4].copy_from_slice(&v_off.to_le_bytes());

        let ks = keys_start + k_off as usize;
        block[ks..ks + 8].copy_from_slice(&oid.to_le_bytes());
        block[ks + 8..ks + 16].copy_from_slice(&xid.to_le_bytes());

        let vs = vals_end - v_off as usize;
        // omap_val_t: ov_flags(0) + ov_size + ov_paddr. `ov_size` is
        // the mapped object's byte size — one block for everything we
        // emit. Leaving it zero makes fsck_apfs reject the object
        // ("apfs: invalid object size (0x0)").
        block[vs + 4..vs + 8].copy_from_slice(&(bs as u32).to_le_bytes());
        block[vs + 8..vs + 16].copy_from_slice(&paddr.to_le_bytes());
    }
    if is_root {
        write_btree_info(
            &mut block,
            bs,
            BTREE_FLAGS_OMAP,
            16,
            16,
            16,
            16,
            tree_key_count,
            tree_node_count,
        );
    }
    sign_block(&mut block);
    Ok(block)
}

/// Build a fixed-KV internal omap root whose keys are 16-byte
/// `(oid, xid)` pairs and whose value slots hold 8-byte physical block
/// addresses of child leaves. The root carries the trailing
/// `btree_info_t`.
fn build_omap_internal_root(
    bs: usize,
    paddr: u64,
    entries: &[((u64, u64), u64)],
    xid: u64,
    tree_key_count: u64,
    tree_node_count: u64,
) -> Result<Vec<u8>> {
    let mut block = vec![0u8; bs];
    block[8..16].copy_from_slice(&paddr.to_le_bytes());
    block[16..24].copy_from_slice(&xid.to_le_bytes());
    block[24..28].copy_from_slice(&(OBJECT_TYPE_BTREE | OBJ_PHYSICAL).to_le_bytes());
    block[28..32].copy_from_slice(&OBJECT_TYPE_OMAP.to_le_bytes());

    let flags = BTNODE_ROOT | BTNODE_FIXED_KV_SIZE;
    block[32..34].copy_from_slice(&flags.to_le_bytes());
    block[34..36].copy_from_slice(&1u16.to_le_bytes()); // level = 1
    block[36..40].copy_from_slice(&(entries.len() as u32).to_le_bytes());

    // An internal fixed-KV node's values are 8-byte child pointers.
    let toc_len = toc_space_fixed(bs, true, 16, 8);
    block[40..42].copy_from_slice(&0u16.to_le_bytes());
    block[42..44].copy_from_slice(&(toc_len as u16).to_le_bytes());

    let toc_base = 56;
    let keys_start = toc_base + toc_len;
    let vals_end = bs - BTREE_INFO_SIZE;
    write_node_free_space(
        &mut block,
        keys_start,
        vals_end,
        entries.len() * 16,
        entries.len() * 8,
    );
    // Each entry uses 4 (ToC) + 16 (key) + 8 (child paddr) = 28 bytes.
    if entries.len() * 28 + 56 + BTREE_INFO_SIZE > bs {
        return Err(crate::Error::Unsupported(format!(
            "apfs writer: {} omap internal entries overflow one block",
            entries.len()
        )));
    }

    for (i, &((oid, xid), child_paddr)) in entries.iter().enumerate() {
        let k_off = (i * 16) as u16;
        // Internal values are 8 bytes per slot.
        let v_off = ((i + 1) * 8) as u16;
        block[toc_base + i * 4..toc_base + i * 4 + 2].copy_from_slice(&k_off.to_le_bytes());
        block[toc_base + i * 4 + 2..toc_base + i * 4 + 4].copy_from_slice(&v_off.to_le_bytes());

        let ks = keys_start + k_off as usize;
        block[ks..ks + 8].copy_from_slice(&oid.to_le_bytes());
        block[ks + 8..ks + 16].copy_from_slice(&xid.to_le_bytes());

        let vs = vals_end - v_off as usize;
        block[vs..vs + 8].copy_from_slice(&child_paddr.to_le_bytes());
    }
    // Root info: bt_key_size=16, bt_val_size=16 (leaf payload size; the
    // reader needs this to know how big leaf entries are).
    write_btree_info(
        &mut block,
        bs,
        BTREE_FLAGS_OMAP,
        16,
        16,
        16,
        16,
        tree_key_count,
        tree_node_count,
    );
    sign_block(&mut block);
    Ok(block)
}

/// Effective payload capacity for an fs-tree leaf (root and non-root use
/// the same conservative figure that includes the trailing
/// `btree_info_t`). Each record consumes 8 ToC bytes + key + val.
fn leaf_payload_capacity(bs: usize) -> usize {
    bs - 56 - BTREE_INFO_SIZE
}

/// Pack a sorted record list into one or more leaf groups, each of
/// which fits inside `cap` bytes when accounting for ToC overhead.
fn pack_records_into_leaves(records: &[FsRecord], cap: usize) -> Result<Vec<Vec<FsRecord>>> {
    if records.is_empty() {
        return Ok(vec![Vec::new()]);
    }
    // A leaf of `n` records costs its ToC (rounded up to whole
    // `BTREE_TOC_ENTRY_INCREMENT`s, see `toc_space_var`) plus the key
    // and value bytes.
    let mut leaves: Vec<Vec<FsRecord>> = Vec::new();
    let mut cur: Vec<FsRecord> = Vec::new();
    let mut cur_bytes: usize = 0;
    for r in records {
        let needed = r.key.len() + r.val.len();
        if toc_space_var(1) + needed > cap {
            return Err(crate::Error::Unsupported(format!(
                "apfs writer: single fs-tree record ({} bytes) does not fit in a leaf (cap {})",
                needed, cap
            )));
        }
        if toc_space_var(cur.len() + 1) + cur_bytes + needed > cap && !cur.is_empty() {
            leaves.push(std::mem::take(&mut cur));
            cur_bytes = 0;
        }
        cur.push(r.clone());
        cur_bytes += needed;
    }
    if !cur.is_empty() {
        leaves.push(cur);
    }
    Ok(leaves)
}

/// Build a variable-KV fs-tree leaf node holding the given (already-
/// sorted) `records`. When `is_root` is true the node carries
/// `BTNODE_ROOT` and a trailing `btree_info_t`. Both root-leaf (depth 1)
/// and non-root leaf (depth 2) callers use this builder; the root flag
/// is set accordingly.
#[allow(clippy::too_many_arguments)]
fn build_fs_leaf(
    records: &[FsRecord],
    bs: usize,
    vid: u64,
    is_root: bool,
    xid: u64,
    tree_key_count: u64,
    tree_node_count: u64,
    kind: TreeKind,
    physical: bool,
) -> Result<Vec<u8>> {
    let mut block = vec![0u8; bs];
    // obj_phys — B-tree objects whose subtype names the tree's contents
    // (FSTREE, BLOCKREFTREE, SNAPMETATREE). A physical tree's node oid
    // is its block address.
    block[8..16].copy_from_slice(&vid.to_le_bytes());
    block[16..24].copy_from_slice(&xid.to_le_bytes());
    let obj_type = if is_root {
        OBJECT_TYPE_BTREE
    } else {
        OBJECT_TYPE_BTREE_NODE
    };
    let storage = if physical { OBJ_PHYSICAL } else { 0 };
    block[24..28].copy_from_slice(&(obj_type | storage).to_le_bytes());
    block[28..32].copy_from_slice(&kind.subtype.to_le_bytes());

    let mut flags = BTNODE_LEAF;
    if is_root {
        flags |= BTNODE_ROOT;
    }
    block[32..34].copy_from_slice(&flags.to_le_bytes());
    block[34..36].copy_from_slice(&0u16.to_le_bytes()); // level
    block[36..40].copy_from_slice(&(records.len() as u32).to_le_bytes());

    let toc_len = toc_space_var(records.len());
    block[40..42].copy_from_slice(&0u16.to_le_bytes());
    block[42..44].copy_from_slice(&(toc_len as u16).to_le_bytes());

    let toc_base = 56;
    let keys_start = toc_base + toc_len;
    let vals_end = if is_root { bs - BTREE_INFO_SIZE } else { bs };

    // Compute total bytes needed.
    let mut total_keys = 0usize;
    let mut total_vals = 0usize;
    for r in records {
        total_keys += r.key.len();
        total_vals += r.val.len();
    }
    write_node_free_space(&mut block, keys_start, vals_end, total_keys, total_vals);
    if keys_start + total_keys + total_vals > vals_end {
        return Err(crate::Error::Unsupported(format!(
            "apfs writer: {} fs-tree records don't fit in one leaf (need {} key bytes + {} val bytes)",
            records.len(),
            total_keys,
            total_vals,
        )));
    }

    let mut k_cursor: usize = 0;
    let mut v_cursor_back: usize = 0;
    for (i, r) in records.iter().enumerate() {
        let k_off = k_cursor as u16;
        let k_len = r.key.len() as u16;
        v_cursor_back += r.val.len();
        let v_off = v_cursor_back as u16;
        let v_len = r.val.len() as u16;
        block[toc_base + i * 8..toc_base + i * 8 + 2].copy_from_slice(&k_off.to_le_bytes());
        block[toc_base + i * 8 + 2..toc_base + i * 8 + 4].copy_from_slice(&k_len.to_le_bytes());
        block[toc_base + i * 8 + 4..toc_base + i * 8 + 6].copy_from_slice(&v_off.to_le_bytes());
        block[toc_base + i * 8 + 6..toc_base + i * 8 + 8].copy_from_slice(&v_len.to_le_bytes());
        let ks = keys_start + k_off as usize;
        block[ks..ks + r.key.len()].copy_from_slice(&r.key);
        let vs = vals_end - v_off as usize;
        block[vs..vs + r.val.len()].copy_from_slice(&r.val);
        k_cursor += r.key.len();
    }

    if is_root {
        // Variable-KV tree: bt_key_size / bt_val_size stay 0 and the
        // longest-key / longest-val fields carry the real maxima.
        let longest_key = records.iter().map(|r| r.key.len()).max().unwrap_or(0) as u32;
        let longest_val = records.iter().map(|r| r.val.len()).max().unwrap_or(0) as u32;
        write_btree_info(
            &mut block,
            bs,
            kind.info_flags,
            0,
            0,
            longest_key,
            longest_val,
            tree_key_count,
            tree_node_count,
        );
    }

    sign_block(&mut block);
    Ok(block)
}

/// Build a variable-KV fs-tree *internal* root pointing at child leaves
/// via virtual oids. Each `(key_bytes, child_vid)` entry is laid out
/// using the same kvloc_t-style ToC as a leaf, but the value bytes are
/// always 8 (the child vid in little-endian).
#[allow(clippy::too_many_arguments)]
fn build_fs_internal_root(
    entries: &[(Vec<u8>, u64)],
    bs: usize,
    root_vid: u64,
    xid: u64,
    longest_key: u32,
    longest_val: u32,
    tree_key_count: u64,
    tree_node_count: u64,
    kind: TreeKind,
    physical: bool,
) -> Result<Vec<u8>> {
    let mut block = vec![0u8; bs];
    block[8..16].copy_from_slice(&root_vid.to_le_bytes());
    block[16..24].copy_from_slice(&xid.to_le_bytes());
    let storage = if physical { OBJ_PHYSICAL } else { 0 };
    block[24..28].copy_from_slice(&(OBJECT_TYPE_BTREE | storage).to_le_bytes());
    block[28..32].copy_from_slice(&kind.subtype.to_le_bytes());

    let flags = BTNODE_ROOT; // not leaf, var-KV
    block[32..34].copy_from_slice(&flags.to_le_bytes());
    block[34..36].copy_from_slice(&1u16.to_le_bytes()); // level = 1
    block[36..40].copy_from_slice(&(entries.len() as u32).to_le_bytes());

    let toc_len = toc_space_var(entries.len());
    block[40..42].copy_from_slice(&0u16.to_le_bytes());
    block[42..44].copy_from_slice(&(toc_len as u16).to_le_bytes());

    let toc_base = 56;
    let keys_start = toc_base + toc_len;
    let vals_end = bs - BTREE_INFO_SIZE;

    let mut total_keys = 0usize;
    for (kb, _) in entries {
        total_keys += kb.len();
    }
    let total_vals = entries.len() * 8;
    write_node_free_space(&mut block, keys_start, vals_end, total_keys, total_vals);
    if keys_start + total_keys + total_vals > vals_end {
        return Err(crate::Error::Unsupported(format!(
            "apfs writer: {} fs-tree internal entries don't fit in one root \
             (need {} key bytes + {} val bytes)",
            entries.len(),
            total_keys,
            total_vals,
        )));
    }

    let mut k_cursor: usize = 0;
    let mut v_cursor_back: usize = 0;
    for (i, (kb, child_vid)) in entries.iter().enumerate() {
        let k_off = k_cursor as u16;
        let k_len = kb.len() as u16;
        v_cursor_back += 8;
        let v_off = v_cursor_back as u16;
        let v_len = 8u16;
        block[toc_base + i * 8..toc_base + i * 8 + 2].copy_from_slice(&k_off.to_le_bytes());
        block[toc_base + i * 8 + 2..toc_base + i * 8 + 4].copy_from_slice(&k_len.to_le_bytes());
        block[toc_base + i * 8 + 4..toc_base + i * 8 + 6].copy_from_slice(&v_off.to_le_bytes());
        block[toc_base + i * 8 + 6..toc_base + i * 8 + 8].copy_from_slice(&v_len.to_le_bytes());

        let ks = keys_start + k_off as usize;
        block[ks..ks + kb.len()].copy_from_slice(kb);
        let vs = vals_end - v_off as usize;
        block[vs..vs + 8].copy_from_slice(&child_vid.to_le_bytes());

        k_cursor += kb.len();
    }
    // Trailing btree_info_t — the counts are for the whole tree, not
    // just this node.
    write_btree_info(
        &mut block,
        bs,
        kind.info_flags,
        0,
        0,
        longest_key,
        longest_val,
        tree_key_count,
        tree_node_count,
    );
    sign_block(&mut block);
    Ok(block)
}

/// Build a `checkpoint_map_phys_t` with a single `checkpoint_mapping_t`
/// entry. Fsck walks this map to resolve the NXSB's ephemeral
/// `nx_spaceman_oid` to the physical block where `spaceman_phys_t` was
/// written.
///
/// On-disk layout (per Apple File System Reference):
///
/// ```text
///   0..32   obj_phys_t
///  32..36   cpm_flags (CHECKPOINT_MAP_LAST = 0x1)
///  36..40   cpm_count (number of entries, here 1)
///  40..80   checkpoint_mapping_t (40 bytes per entry)
/// ```
fn build_chkmap(bs: usize, paddr: u64, entries: &[(u32, u64, u64)], xid: u64) -> Result<Vec<u8>> {
    if bs < 40 + entries.len() * 40 {
        return Err(crate::Error::Unsupported(format!(
            "apfs: block size {bs} too small for a {}-entry checkpoint map",
            entries.len()
        )));
    }
    let mut buf = vec![0u8; bs];
    buf[8..16].copy_from_slice(&paddr.to_le_bytes());
    buf[16..24].copy_from_slice(&xid.to_le_bytes());
    buf[24..28].copy_from_slice(&(OBJECT_TYPE_CHECKPOINT_MAP | OBJ_PHYSICAL).to_le_bytes());
    // cpm_flags = CHECKPOINT_MAP_LAST.
    buf[32..36].copy_from_slice(&1u32.to_le_bytes());
    buf[36..40].copy_from_slice(&(entries.len() as u32).to_le_bytes()); // cpm_count

    // checkpoint_mapping_t (40 bytes each) from offset 40.
    for (i, &(entry_type, entry_oid, entry_paddr)) in entries.iter().enumerate() {
        let o = 40 + i * 40;
        // cpm_type / cpm_subtype mirror the target object's o_type/o_subtype.
        buf[o..o + 4].copy_from_slice(&entry_type.to_le_bytes());
        buf[o + 4..o + 8].copy_from_slice(&0u32.to_le_bytes()); // cpm_subtype
        // cpm_size = block size (we copy one block at this paddr).
        buf[o + 8..o + 12].copy_from_slice(&(bs as u32).to_le_bytes());
        // cpm_pad + cpm_fs_oid stay zero (not volume-scoped objects).
        buf[o + 24..o + 32].copy_from_slice(&entry_oid.to_le_bytes()); // cpm_oid
        buf[o + 32..o + 40].copy_from_slice(&entry_paddr.to_le_bytes()); // cpm_paddr
    }
    sign_block(&mut buf);
    Ok(buf)
}

/// Build the container's reaper object — the ephemeral queue APFS uses
/// to finish deleting large objects across checkpoints. We never queue
/// anything, so this is the empty form: `nr_next_reap_id` 1, the
/// "buffer holds a mapping" flag set, and a state buffer filling the
/// rest of the block. `fsck_apfs` requires the container's checkpoint
/// data area to carry at least the spaceman and the reaper.
fn build_reaper(bs: usize, oid: u64, xid: u64) -> Result<Vec<u8>> {
    if bs < 112 {
        return Err(crate::Error::Unsupported(format!(
            "apfs: block size {bs} too small for a reaper"
        )));
    }
    let mut buf = vec![0u8; bs];
    buf[8..16].copy_from_slice(&oid.to_le_bytes());
    buf[16..24].copy_from_slice(&xid.to_le_bytes());
    buf[24..28].copy_from_slice(&(OBJECT_TYPE_NX_REAPER | OBJ_EPHEMERAL).to_le_bytes());
    buf[32..40].copy_from_slice(&1u64.to_le_bytes()); // nr_next_reap_id
    buf[64..68].copy_from_slice(&1u32.to_le_bytes()); // nr_flags = NR_BHM_FLAG
    buf[108..112].copy_from_slice(&((bs - 112) as u32).to_le_bytes()); // nr_state_buffer_size
    sign_block(&mut buf);
    Ok(buf)
}

/// Derive a deterministic 16-byte UUID-like value from a name + a salt.
/// We avoid a UUID dependency by mixing the inputs through a simple
/// xor-shift PRNG seeded with the bytes; not cryptographically random,
/// but stable across runs which is all we want.
fn derive_uuid(name: &[u8], salt: &[u8]) -> [u8; 16] {
    let mut seed: u64 = 0x6a09_e667_f3bc_c908;
    for &b in name.iter().chain(salt.iter()) {
        seed = seed.wrapping_mul(0x0100_0193).wrapping_add(b as u64);
        seed ^= seed >> 27;
    }
    let mut out = [0u8; 16];
    for chunk in out.chunks_mut(8) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        chunk.copy_from_slice(&seed.to_le_bytes());
    }
    // Set RFC4122 variant + version-4-ish bits so it looks UUID-shaped.
    out[6] = (out[6] & 0x0f) | 0x40;
    out[8] = (out[8] & 0x3f) | 0x80;
    out
}

pub(crate) fn mode_reg(perm: u16) -> u16 {
    0o100_000 | (perm & 0o7777)
}
pub(crate) fn mode_dir(perm: u16) -> u16 {
    0o040_000 | (perm & 0o7777)
}
pub(crate) fn mode_lnk(perm: u16) -> u16 {
    0o120_000 | (perm & 0o7777)
}

#[cfg(test)]
mod tests {
    use super::super::Apfs;
    use super::*;
    use crate::block::MemoryBackend;
    use std::io::{Cursor, Read};

    /// Build a small image with one regular file and round-trip it
    /// through the read path.
    #[test]
    fn write_then_read_single_small_file() {
        let total_blocks = 64u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        {
            let mut w = ApfsWriter::new(&mut dev, total_blocks, bs, "TestVol").unwrap();
            let data = b"hello apfs world";
            let mut r = Cursor::new(data);
            w.add_file_from_reader(2, "hi.txt", 0o644, &mut r, data.len() as u64)
                .unwrap();
            w.finish().unwrap();
        }
        // Now read it back.
        let apfs = Apfs::open(&mut dev).expect("opens the new image");
        assert_eq!(apfs.volume_name(), "TestVol");
        let entries = apfs.list_path(&mut dev, "/").expect("list root");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"hi.txt"), "got names: {names:?}");

        let mut reader = apfs.open_file_reader(&mut dev, "/hi.txt").unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"hello apfs world");
    }

    /// A nested directory round-trips through list_path.
    #[test]
    fn write_then_read_nested_dir() {
        let total_blocks = 64u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        {
            let mut w = ApfsWriter::new(&mut dev, total_blocks, bs, "Vol").unwrap();
            let dir = w.add_dir(2, "sub", 0o755).unwrap();
            let data = b"nested";
            let mut r = Cursor::new(data);
            w.add_file_from_reader(dir, "f", 0o644, &mut r, data.len() as u64)
                .unwrap();
            w.finish().unwrap();
        }
        let apfs = Apfs::open(&mut dev).unwrap();
        let root = apfs.list_path(&mut dev, "/").unwrap();
        assert!(root.iter().any(|e| e.name == "sub"));
        let sub = apfs.list_path(&mut dev, "/sub").unwrap();
        assert!(sub.iter().any(|e| e.name == "f"));
        let mut r = apfs.open_file_reader(&mut dev, "/sub/f").unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"nested");
    }

    /// Symlinks survive a write+read round-trip and report as DT_LNK.
    #[test]
    fn write_then_read_symlink() {
        let total_blocks = 64u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        {
            let mut w = ApfsWriter::new(&mut dev, total_blocks, bs, "Vol").unwrap();
            w.add_symlink(2, "link", 0o777, "/dev/null").unwrap();
            w.finish().unwrap();
        }
        let apfs = Apfs::open(&mut dev).unwrap();
        let entries = apfs.list_path(&mut dev, "/").unwrap();
        let link = entries.iter().find(|e| e.name == "link").unwrap();
        assert!(matches!(link.kind, crate::fs::EntryKind::Symlink));
        assert_eq!(apfs.read_symlink(&mut dev, "/link").unwrap(), "/dev/null");
    }

    /// Multi-volume API: a freshly written image with one volume
    /// reports exactly one populated slot, and `open_volume(0)` opens
    /// the same volume as `Apfs::open`.
    #[test]
    fn list_and_open_single_volume_slot() {
        let total_blocks = 64u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        {
            let w = ApfsWriter::new(&mut dev, total_blocks, bs, "OnlyVol").unwrap();
            w.finish().unwrap();
        }
        let vols = Apfs::list_volumes(&mut dev).unwrap();
        assert_eq!(vols.len(), 1);
        assert_eq!(vols[0].name, "OnlyVol");
        assert!(!vols[0].encrypted);
        assert_eq!(vols[0].index, 0);
        let apfs = Apfs::open_volume(&mut dev, 0).unwrap();
        assert_eq!(apfs.volume_name(), "OnlyVol");
        // Opening a missing slot fails cleanly.
        let e = Apfs::open_volume(&mut dev, 5).unwrap_err();
        assert!(matches!(e, crate::Error::InvalidArgument(_)));
    }

    /// `list_snapshots` on a volume without snapshots returns an empty
    /// vector (apfs_snap_meta_tree_oid == 0).
    #[test]
    fn list_snapshots_empty_when_no_tree() {
        let total_blocks = 64u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        {
            let w = ApfsWriter::new(&mut dev, total_blocks, bs, "Vol").unwrap();
            w.finish().unwrap();
        }
        let apfs = Apfs::open(&mut dev).unwrap();
        let snaps = apfs.list_snapshots(&mut dev).unwrap();
        assert!(snaps.is_empty());
        // open_snapshot with a non-existent xid should fail cleanly.
        let e = apfs.open_snapshot(&mut dev, 42).unwrap_err();
        assert!(matches!(e, crate::Error::InvalidArgument(_)));
    }

    /// Streaming invariant — a larger file (multi-block) still works.
    #[test]
    fn write_then_read_multiblock_file() {
        let total_blocks = 128u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        let payload: Vec<u8> = (0..(20 * 1024)).map(|i| (i % 256) as u8).collect();
        {
            let mut w = ApfsWriter::new(&mut dev, total_blocks, bs, "Vol").unwrap();
            let mut r = Cursor::new(payload.clone());
            w.add_file_from_reader(2, "blob", 0o644, &mut r, payload.len() as u64)
                .unwrap();
            w.finish().unwrap();
        }
        let apfs = Apfs::open(&mut dev).unwrap();
        let mut r = apfs.open_file_reader(&mut dev, "/blob").unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    /// Embedded xattrs round-trip through `read_xattrs`.
    #[test]
    fn write_then_read_embedded_xattrs() {
        let total_blocks = 64u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        {
            let mut w = ApfsWriter::new(&mut dev, total_blocks, bs, "Vol").unwrap();
            let mut r = Cursor::new(b"x");
            w.add_file_from_reader(2, "f", 0o644, &mut r, 1).unwrap();
            // Look up the file's oid by scanning the directory.
            // The first new file gets oid 17 (we start at 16, root used 16's
            // slot? actually next_oid begins at 16 — first alloc returns 16).
            // But we don't depend on the value; we'll re-look it up on read.
            w.add_xattr(2, "user.note", b"hello world").unwrap();
            w.add_xattr(2, "user.lang", b"en_US").unwrap();
            w.finish().unwrap();
        }
        let apfs = Apfs::open(&mut dev).unwrap();
        let xs = apfs.read_xattrs(&mut dev, "/").unwrap();
        assert_eq!(
            xs.get("user.note").map(Vec::as_slice),
            Some(&b"hello world"[..])
        );
        assert_eq!(xs.get("user.lang").map(Vec::as_slice), Some(&b"en_US"[..]));
    }

    /// Xattrs attached to a non-root inode are surfaced under that
    /// inode's path (not under "/").
    #[test]
    fn xattr_attached_to_file_path() {
        let total_blocks = 64u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        {
            let mut w = ApfsWriter::new(&mut dev, total_blocks, bs, "Vol").unwrap();
            let mut r = Cursor::new(b"data");
            let oid = w
                .add_file_from_reader(2, "doc.txt", 0o644, &mut r, 4)
                .unwrap();
            w.add_xattr(oid, "com.apple.lastuseddate#PS", &[1, 2, 3, 4])
                .unwrap();
            w.finish().unwrap();
        }
        let apfs = Apfs::open(&mut dev).unwrap();
        // Root has no xattrs.
        let root_xs = apfs.read_xattrs(&mut dev, "/").unwrap();
        assert!(root_xs.is_empty());
        // The file does.
        let xs = apfs.read_xattrs(&mut dev, "/doc.txt").unwrap();
        assert_eq!(
            xs.get("com.apple.lastuseddate#PS").map(Vec::as_slice),
            Some(&[1u8, 2, 3, 4][..])
        );
    }

    /// Oversized xattr values return `Unsupported`.
    #[test]
    fn xattr_too_big_unsupported() {
        let total_blocks = 64u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        let mut w = ApfsWriter::new(&mut dev, total_blocks, bs, "Vol").unwrap();
        let big = vec![0u8; APFS_XATTR_MAX_EMBEDDED_SIZE + 1];
        let e = w.add_xattr(2, "user.too_big", &big).unwrap_err();
        assert!(matches!(e, crate::Error::Unsupported(_)));
    }

    /// Multi-leaf fs-tree: enough small files to overflow a single 4 KiB
    /// leaf, then read them back via the reader's multi-level walker.
    #[test]
    fn write_then_read_multi_leaf_fs_tree() {
        let total_blocks = 256u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        let n_files: usize = 80; // each file ≈ 50 bytes of fs-tree records → ~4 KiB leaf @ 4 KiB blocks
        let payloads: Vec<Vec<u8>> = (0..n_files)
            .map(|i| format!("file-{i:03}-payload").into_bytes())
            .collect();
        {
            let mut w = ApfsWriter::new(&mut dev, total_blocks, bs, "Vol").unwrap();
            for (i, p) in payloads.iter().enumerate() {
                let name = format!("f{i:03}");
                let mut r = Cursor::new(p.clone());
                w.add_file_from_reader(2, &name, 0o644, &mut r, p.len() as u64)
                    .unwrap();
            }
            w.finish().unwrap();
        }
        let apfs = Apfs::open(&mut dev).unwrap();
        let entries = apfs.list_path(&mut dev, "/").unwrap();
        assert!(
            entries.len() >= n_files,
            "expected at least {} entries, got {}",
            n_files,
            entries.len()
        );
        // Spot-check a few file contents.
        for &i in &[0usize, 1, n_files / 2, n_files - 1] {
            let name = format!("/f{i:03}");
            let mut r = apfs.open_file_reader(&mut dev, &name).unwrap();
            let mut out = Vec::new();
            r.read_to_end(&mut out).unwrap();
            assert_eq!(out, payloads[i], "mismatch for {name}");
        }
    }

    /// `pack_records_into_leaves` splits when the cumulative byte count
    /// would exceed `cap`, and never emits an empty leaf.
    #[test]
    fn pack_records_splits_on_capacity() {
        let r = |k: u8, v_len: usize| FsRecord {
            key: vec![k; 8],
            val: vec![0u8; v_len],
        };
        let recs = vec![r(1, 100), r(2, 100), r(3, 100)];
        // The ToC is reserved 8 entries (64 bytes) at a time.
        // cap = 64 + (8 + 100) = 172 → exactly one record per leaf.
        let leaves = pack_records_into_leaves(&recs, 172).unwrap();
        assert_eq!(leaves.len(), 3);
        // cap = 64 + 2 * (8 + 100) = 280 → two records per leaf.
        let leaves = pack_records_into_leaves(&recs, 280).unwrap();
        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[0].len(), 2);
        assert_eq!(leaves[1].len(), 1);
    }

    /// The main free queue's node limit and the checkpoint data area
    /// follow `newfs_apfs` exactly at every measured transition (the
    /// kernel refuses a container whose node limit is off by one).
    #[test]
    fn size_dependent_limits_match_newfs_apfs() {
        for (blocks, limit) in [
            (1000, 1),
            (4544, 1),
            (4545, 3),
            (9088, 3),
            (13632, 3),
            (13633, 4),
            (22721, 6),
            (32768, 8),
            (36352, 8),
            (36353, 9),
            (40897, 10),
            (54529, 13),
            (65536, 15),
            (131072, 29),
            (196608, 44),
            (262143, 58),
            (262144, 116),
            (524288, 231),
            (1048575, 462),
            (1048576, 512),
            (4194304, 512),
        ] {
            assert_eq!(main_fq_node_limit(blocks), limit, "{blocks} blocks");
        }
        for (blocks, data) in [
            (4096, 52),
            (8192, 124),
            (32768, 304),
            (40000, 308),
            (65536, 332),
        ] {
            assert_eq!(xp_data_blocks_for(blocks), data, "{blocks} blocks");
        }
        // Tiny test images keep the fsck minimum.
        assert_eq!(xp_data_blocks_for(64), XP_DATA_BLOCKS_MIN);
    }

    // ---- Spaceman tests ----
    //
    // `fsck_apfs` is not packaged for Linux (no `apt`/`brew` binary is
    // available on this host or in CI), so we can't run it directly.
    // Instead we round-trip a tiny image through the writer and verify
    // that the emitted `spaceman_phys_t` + CIB + bitmap blocks are
    // internally consistent and agree with the writer's known
    // allocations. If a host ever does have `fsck_apfs`, see the
    // separate `apfs_fsck_external` ignored test for the wiring.

    use crate::block::BlockDevice;
    use crate::fs::apfs::spaceman::{count_used_bits, decode_cib_entries, decode_spaceman};

    /// Read the `paddr`-th 4 KiB block off `dev` as a Vec<u8>.
    fn read_block(dev: &mut dyn BlockDevice, paddr: u64, bs: u32) -> Vec<u8> {
        let mut buf = vec![0u8; bs as usize];
        dev.read_at(paddr * bs as u64, &mut buf).unwrap();
        buf
    }

    /// Verify spaceman+CIB+bitmap consistency: every chunk_info entry's
    /// free_count agrees with its bitmap's cleared-bit count, and the
    /// total free_count agrees with the spaceman header.
    fn assert_spaceman_consistent(dev: &mut dyn BlockDevice, bs: u32, total_blocks: u64) {
        // Spaceman lives at SPACEMAN_PADDR.
        let sm = read_block(dev, SPACEMAN_PADDR, bs);
        let dec = decode_spaceman(&sm).expect("decode spaceman_phys_t");
        assert_eq!(dec.block_size, bs);
        assert_eq!(dec.blocks_per_chunk, bs * 8);
        assert_eq!(dec.main_block_count, total_blocks);
        assert_eq!(dec.main_cab_count, 0);
        assert_eq!(dec.main_cib_count, 1);
        assert_eq!(dec.main_chunk_count, total_blocks.div_ceil((bs * 8) as u64));

        // CIB block (decoded from sm.cib_paddr).
        let cib = read_block(dev, dec.cib_paddr, bs);
        let entries = decode_cib_entries(&cib).expect("decode CIB");
        assert_eq!(entries.len() as u64, dec.main_chunk_count);

        let mut free_total: u64 = 0;
        let bpc = bs * 8;
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.addr, (i as u64) * bpc as u64, "chunk addr off");
            let expected_blocks =
                ((i as u64 + 1) * bpc as u64).min(total_blocks) - (i as u64) * bpc as u64;
            assert_eq!(
                e.block_count as u64, expected_blocks,
                "chunk {} block_count off",
                i
            );
            // Cross-check free_count vs bitmap cleared bits.
            let bmap = read_block(dev, e.bitmap_addr, bs);
            let used = count_used_bits(&bmap, e.block_count);
            let free = e.block_count - used;
            assert_eq!(
                free, e.free_count,
                "chunk {} free_count {} disagrees with bitmap (used={})",
                i, e.free_count, used
            );
            free_total += free as u64;
        }
        assert_eq!(
            free_total, dec.main_free_count,
            "spaceman free_count disagrees with sum of chunk free counts",
        );
    }

    /// Smoke test: the spaceman emitted for a tiny image accurately
    /// reflects the writer's allocations.
    #[test]
    fn spaceman_reflects_bump_allocations() {
        let total_blocks = 64u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        {
            let mut w = ApfsWriter::new(&mut dev, total_blocks, bs, "Vol").unwrap();
            let data = b"abc";
            let mut r = Cursor::new(data);
            w.add_file_from_reader(2, "f", 0o644, &mut r, data.len() as u64)
                .unwrap();
            w.finish().unwrap();
        }
        assert_spaceman_consistent(&mut dev, bs, total_blocks);
        // Every used block in our bitmap must actually be a block we
        // wrote into. For the smoke check, just confirm block 0 (NXSB
        // label) is marked used and the last block of the container
        // (which the writer never touches) is marked free.
        let sm = read_block(&mut dev, SPACEMAN_PADDR, bs);
        let dec = decode_spaceman(&sm).unwrap();
        let cib = read_block(&mut dev, dec.cib_paddr, bs);
        let entries = decode_cib_entries(&cib).unwrap();
        let bmap = read_block(&mut dev, entries[0].bitmap_addr, bs);
        assert!(bmap[0] & 0x01 != 0, "block 0 (NXSB label) must be used");
        let last_bit = (total_blocks - 1) as usize;
        assert!(
            bmap[last_bit / 8] & (1 << (last_bit % 8)) == 0,
            "last block of container must be free"
        );
    }

    /// Larger image: multi-block file, still inside chunk 0. The
    /// spaceman bitmap must report the file's extent as "used".
    #[test]
    fn spaceman_marks_file_extent_used() {
        let total_blocks = 256u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        let payload: Vec<u8> = (0..(20 * 1024)).map(|i| (i % 256) as u8).collect();
        // First pass: write *just* metadata (empty image) to see how
        // many blocks the writer naturally consumes.
        let used_blocks_before = {
            let mut dev1 = MemoryBackend::new(total_blocks * bs as u64);
            let w1 = ApfsWriter::new(&mut dev1, total_blocks, bs, "V").unwrap();
            w1.finish().unwrap();
            let sm1 = read_block(&mut dev1, SPACEMAN_PADDR, bs);
            let d1 = decode_spaceman(&sm1).unwrap();
            total_blocks - d1.main_free_count
        };
        {
            let mut w = ApfsWriter::new(&mut dev, total_blocks, bs, "V").unwrap();
            let mut r = Cursor::new(payload.clone());
            w.add_file_from_reader(2, "blob", 0o644, &mut r, payload.len() as u64)
                .unwrap();
            w.finish().unwrap();
        }
        assert_spaceman_consistent(&mut dev, bs, total_blocks);
        let sm = read_block(&mut dev, SPACEMAN_PADDR, bs);
        let d = decode_spaceman(&sm).unwrap();
        let used_blocks_after = total_blocks - d.main_free_count;
        // Writing a 20 KiB file consumes at least 5 extra data blocks
        // (plus its fs-tree-record bookkeeping). The bitmap must
        // reflect that growth.
        assert!(
            used_blocks_after >= used_blocks_before + 5,
            "expected at least 5 more used blocks after adding 20 KiB file \
             (was {used_blocks_before}, now {used_blocks_after})"
        );
    }

    /// A freshly formatted spaceman is laid out the way `newfs_apfs`
    /// lays it out: an internal pool of 3 blocks per chunk + CIB that
    /// holds the CIB and the chunk bitmaps (and is tracked by the first
    /// IP-bitmap ring slot), empty free queues with no trees, and a
    /// zero allocation-zone table.
    #[test]
    fn spaceman_matches_newfs_apfs_layout() {
        let total_blocks = 128u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        {
            let w = ApfsWriter::new(&mut dev, total_blocks, bs, "Vol").unwrap();
            w.finish().unwrap();
        }
        let sm = read_block(&mut dev, SPACEMAN_PADDR, bs);
        let dec = decode_spaceman(&sm).expect("decode spaceman_phys_t");
        assert_eq!(dec.flags & 0x1, 0x1, "SM_FLAG_VERSIONED must be set");
        assert_eq!(dec.ip_bm_tx_multiplier, 16);
        assert_eq!(dec.ip_block_count, 6, "3 × (1 chunk + 1 CIB)");
        assert_eq!(dec.ip_bm_size_in_blocks, 1);
        assert_eq!(dec.ip_bm_block_count, 16);
        assert!(dec.ip_base + dec.ip_block_count <= total_blocks);
        assert!(dec.ip_bm_base + 16 <= dec.ip_base || dec.ip_base + 6 <= dec.ip_bm_base);
        // The CIB and the chunk bitmap live in the pool, and the live IP
        // bitmap marks exactly those two blocks.
        assert_eq!(dec.cib_paddr, dec.ip_base);
        let cib = read_block(&mut dev, dec.cib_paddr, bs);
        let entries = decode_cib_entries(&cib).unwrap();
        assert_eq!(entries[0].bitmap_addr, dec.ip_base + 1);
        let ip_bm = read_block(&mut dev, dec.ip_bm_base, bs);
        assert_eq!(ip_bm[0], 0b11);
        assert!(ip_bm[1..].iter().all(|&b| b == 0));
        // Free queues: no tree yet, node limits 1 / ≥1 / 0.
        assert_eq!(dec.sfq_tree_oids, [0, 0, 0]);
        assert_eq!(dec.sfq_node_limits[0], 1);
        assert!(dec.sfq_node_limits[1] >= 1);
        assert_eq!(dec.sfq_node_limits[2], 0);
        assert_eq!(dec.datazone_main_zone0_start, 0);
        assert_eq!(dec.datazone_main_zone0_end, 0);
        // The pool itself is part of the used prefix.
        assert_spaceman_consistent(&mut dev, bs, total_blocks);
    }

    /// The checkpoint map at block 1 must resolve the NXSB's
    /// `nx_spaceman_oid` and `nx_reaper_oid` to their physical blocks —
    /// both are ephemeral objects living in the checkpoint data area.
    #[test]
    fn checkpoint_map_resolves_spaceman_oid() {
        let total_blocks = 64u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        {
            let w = ApfsWriter::new(&mut dev, total_blocks, bs, "V").unwrap();
            w.finish().unwrap();
        }
        // NXSB at NXSB_LIVE_PADDR: nx_spaceman_oid is at offset 152..160.
        let nxsb = read_block(&mut dev, NXSB_LIVE_PADDR, bs);
        let sm_oid = u64::from_le_bytes(nxsb[152..160].try_into().unwrap());
        // Checkpoint map at CHKMAP_PADDR.
        let chk = read_block(&mut dev, CHKMAP_PADDR, bs);
        // cpm_count at offset 36, then 40-byte checkpoint_mapping_t
        // entries from offset 40: type/subtype/size/pad (16), fs_oid
        // (+16), oid (+24), paddr (+32).
        let cpm_count = u32::from_le_bytes(chk[36..40].try_into().unwrap());
        assert_eq!(cpm_count, 2, "expected spaceman + reaper entries");
        let entry = 40usize;
        let cpm_oid = u64::from_le_bytes(chk[entry + 24..entry + 32].try_into().unwrap());
        let cpm_paddr = u64::from_le_bytes(chk[entry + 32..entry + 40].try_into().unwrap());
        assert_eq!(
            cpm_oid, sm_oid,
            "chkmap oid must match NXSB nx_spaceman_oid"
        );
        assert_eq!(
            cpm_paddr, SPACEMAN_PADDR,
            "spaceman lives at SPACEMAN_PADDR"
        );
        let rp_oid = u64::from_le_bytes(nxsb[168..176].try_into().unwrap());
        let entry = 80usize;
        assert_eq!(
            u64::from_le_bytes(chk[entry + 24..entry + 32].try_into().unwrap()),
            rp_oid,
            "chkmap oid must match NXSB nx_reaper_oid"
        );
        assert_eq!(
            u64::from_le_bytes(chk[entry + 32..entry + 40].try_into().unwrap()),
            SPACEMAN_PADDR + 1,
            "the reaper follows the spaceman in the checkpoint data area"
        );
        // Every virtual / ephemeral oid must be past the reserved range.
        for oid in [sm_oid, rp_oid] {
            assert!(oid >= 1024, "oid {oid} is inside the reserved range");
        }
    }

    /// External `fsck_apfs` smoke test — runs only when the binary is
    /// installed (typically on macOS). Builds a tiny image to a temp
    /// file, then shells out and asserts a clean exit. Linux hosts skip
    /// this test gracefully.
    #[test]
    #[ignore = "requires fsck_apfs (macOS host); see test body"]
    fn apfs_fsck_external() {
        use std::process::Command;
        if Command::new("fsck_apfs").arg("-h").output().is_err() {
            // Tool unavailable — skip without failing.
            return;
        }
        let dir = std::env::temp_dir();
        let path = dir.join("genfs-apfs-spaceman-fsck.img");
        let total_blocks = 256u64;
        let bs = 4096u32;
        let mut dev = MemoryBackend::new(total_blocks * bs as u64);
        {
            let mut w = ApfsWriter::new(&mut dev, total_blocks, bs, "FsckVol").unwrap();
            let mut r = Cursor::new(b"hello");
            w.add_file_from_reader(2, "f.txt", 0o644, &mut r, 5)
                .unwrap();
            w.finish().unwrap();
        }
        // Drain memory backend to file.
        let mut buf = vec![0u8; (total_blocks * bs as u64) as usize];
        dev.read_at(0, &mut buf).unwrap();
        std::fs::write(&path, &buf).unwrap();
        let status = Command::new("fsck_apfs")
            .arg("-n")
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success(), "fsck_apfs reported errors");
    }
}
