//! APFS space manager, laid out the way `newfs_apfs` lays it out.
//!
//! The writer hands `build_spaceman` a description of which container
//! blocks are currently used (the entire prefix from 0 to `next_block`,
//! since we bump-allocate); this module emits:
//!
//! * a `spaceman_phys_t` block with one main-device entry and an inline
//!   array of CIB physical addresses (no CAB indirection — single CIB),
//! * a `chunk_info_block_t` (CIB) containing one `chunk_info_t` per
//!   container chunk,
//! * one allocation-bitmap block per chunk,
//! * the first block of the internal-pool bitmap ring.
//!
//! The CIB and the chunk bitmaps are *internal-pool* objects: they live
//! inside the `sm_ip_base .. sm_ip_base + sm_ip_block_count` range and
//! are tracked by the IP bitmap, not handed out by the main allocator.
//! The kernel copies them on write by allocating from that pool and
//! returning the old copies to the IP free queue, so a CIB placed
//! anywhere else makes the very first transaction after mount free a
//! block the pool does not own.
//!
//! The free queues start out empty with no tree at all
//! (`sfq_tree_oid = 0`), exactly like the first checkpoint
//! `newfs_apfs` writes; the kernel creates the (ephemeral) trees in the
//! checkpoint data area the first time it frees anything.
//!
//! Bitmap convention: a set bit means "used"; cleared bits are free.
//!
//! Layout in the on-disk spaceman_phys_t (offsets from the start of the
//! block, all little-endian; identical to the Apple File System
//! Reference, Space Manager section):
//!
//! ```text
//!   0..32   obj_phys_t (cksum, oid, xid, type=OBJ_EPHEMERAL|0x0005, subtype=0)
//!  32..48   sm_block_size / sm_blocks_per_chunk / sm_chunks_per_cib / sm_cibs_per_cab
//!  48..96   SD_MAIN spaceman_device_t (48 bytes)
//!  96..144  SD_TIER2 spaceman_device_t (only sm_addr_offset is set)
//! 144..148  sm_flags
//! 148..152  sm_ip_bm_tx_multiplier
//! 152..160  sm_ip_block_count
//! 160..164  sm_ip_bm_size_in_blocks
//! 164..168  sm_ip_bm_block_count
//! 168..176  sm_ip_bm_base
//! 176..184  sm_ip_base
//! 184..192  sm_fs_reserve_block_count
//! 192..200  sm_fs_reserve_alloc_count
//! 200..240  SFQ_IP    spaceman_free_queue_t (40 bytes)
//! 240..280  SFQ_MAIN  spaceman_free_queue_t
//! 280..320  SFQ_TIER2 spaceman_free_queue_t
//! 320..322  sm_ip_bm_free_head (u16)
//! 322..324  sm_ip_bm_free_tail (u16)
//! 324..328  sm_ip_bm_xid_offset (u32)
//! 328..332  sm_ip_bitmap_offset (u32)
//! 332..336  sm_ip_bm_free_next_offset (u32)
//! 336..340  sm_version (=1)
//! 340..344  sm_struct_size (= 2520, the end of sm_datazone)
//! 344..2520 sm_datazone (all zero, as newfs_apfs leaves it)
//! 2520..    IP-bitmap xid array, IP-bitmap index array, IP-bitmap
//!           free-list array, then the per-device CIB address arrays
//! ```

use crate::Result;

use super::checksum::fletcher64;

/// `OBJECT_TYPE_SPACEMAN`.
pub(super) const OBJECT_TYPE_SPACEMAN: u32 = 0x0000_0005;
/// `OBJECT_TYPE_SPACEMAN_CIB`.
pub(super) const OBJECT_TYPE_SPACEMAN_CIB: u32 = 0x0000_0007;

/// `OBJ_PHYSICAL`.
const OBJ_PHYSICAL: u32 = 0x4000_0000;
/// `OBJ_EPHEMERAL`.
const OBJ_EPHEMERAL: u32 = 0x8000_0000;

/// `SM_FLAG_VERSIONED` — set when `sm_version` is meaningful.
const SM_FLAG_VERSIONED: u32 = 0x0000_0001;

/// `SPACEMAN_IP_BM_TX_MULTIPLIER` (Apple File System Reference,
/// "Internal-Pool Bitmap": 16). It is also the number of blocks in the
/// IP-bitmap ring (`sm_ip_bm_block_count`).
pub(super) const SPACEMAN_IP_BM_TX_MULTIPLIER: u32 = 16;

/// `SPACEMAN_IP_BM_INDEX_INVALID` — free-list terminator / "slot in use"
/// marker in the IP-bitmap free-next array.
const SPACEMAN_IP_BM_INDEX_INVALID: u16 = 0xffff;

/// `SM_ALLOCZONE_NUM_PREVIOUS_BOUNDARIES`.
const SM_ALLOCZONE_NUM_PREVIOUS_BOUNDARIES: usize = 7;

/// `SM_DATAZONE_ALLOCZONE_COUNT` — zones per device in `sm_datazone`.
const SM_DATAZONE_ALLOCZONE_COUNT: usize = 8;

/// `SD_COUNT` — devices in `sm_datazone[][]` (main + tier2).
const SD_COUNT: usize = 2;

/// `SD_MAIN` device index.
#[cfg(test)]
const SD_MAIN: usize = 0;

/// Size of one `spaceman_allocation_zone_info_phys_t`:
/// 16 (current) + 7*16 (previous) + 2 (zone_id) + 2 (prev_index) + 4
/// (reserved) = 136 bytes.
const ALLOC_ZONE_INFO_SIZE: usize = 16 + SM_ALLOCZONE_NUM_PREVIOUS_BOUNDARIES * 16 + 8;

/// Size of the entire `sm_datazone` substructure.
const DATAZONE_SIZE: usize = SD_COUNT * SM_DATAZONE_ALLOCZONE_COUNT * ALLOC_ZONE_INFO_SIZE;

/// Byte offset of `sm_datazone` inside `spaceman_phys_t`.
const SM_DATAZONE_OFFSET: usize = 344;

/// End of the fixed `spaceman_phys_t` structure (`sm_struct_size`); the
/// variable-length arrays start here.
const SM_STRUCT_SIZE: usize = SM_DATAZONE_OFFSET + DATAZONE_SIZE;

/// Number of blocks one bitmap block can track at `block_size = 4096`.
/// Each byte tracks 8 blocks, so a 4096-byte bitmap covers 32 768
/// blocks. The spec ties this to `sm_blocks_per_chunk = 8 * block_size`.
pub(super) fn blocks_per_chunk(block_size: usize) -> u64 {
    (block_size as u64) * 8
}

/// Number of `chunk_info_t` entries (32 bytes each) that fit in a single
/// CIB block after the 40-byte header.
pub(super) fn chunks_per_cib(block_size: usize) -> u32 {
    ((block_size - 40) / 32) as u32
}

/// Internal-pool size for a container with `chunks` chunks and a single
/// CIB: three blocks per chunk bitmap / CIB / CAB, which is what
/// `newfs_apfs` reserves (6 blocks for one chunk, 9 for two, 27 for
/// eight, 195 for sixty-four) and what `fsck_apfs` checks
/// ("spaceman ip block count is bad").
pub(super) fn ip_block_count(chunks: u64) -> u64 {
    3 * (chunks + 1)
}

/// Information needed to emit the spaceman.
pub(super) struct SpacemanLayout {
    /// Block size of the container (typically 4096).
    pub block_size: usize,
    /// Total number of blocks in the container.
    pub total_blocks: u64,
    /// XID stamped on every emitted spaceman / CIB / bitmap block.
    pub xid: u64,
    /// Ephemeral oid for the spaceman header. Matches what the NXSB
    /// publishes in `nx_spaceman_oid` and what the checkpoint map
    /// resolves to the spaceman's physical block.
    pub spaceman_oid: u64,
    /// All block ranges considered used by the writer. Inclusive start,
    /// exclusive end. The main bitmap is generated by ORing the bit for
    /// each block in every range; the ranges must cover the IP-bitmap
    /// ring and the internal pool itself.
    pub used_ranges: Vec<(u64, u64)>,
    /// First block of the internal pool (`sm_ip_base`). Must hold
    /// [`ip_block_count`] blocks; the CIB goes in its first block and
    /// the chunk bitmaps right after it.
    pub ip_base: u64,
    /// First block of the IP-bitmap ring (`sm_ip_bm_base`),
    /// [`SPACEMAN_IP_BM_TX_MULTIPLIER`] blocks long.
    pub ip_bm_base: u64,
    /// `sfq_tree_node_limit` of the main free queue.
    pub main_fq_node_limit: u16,
}

/// Emitted spaceman artifact.
pub(super) struct EmittedSpaceman {
    pub spaceman_block: Vec<u8>,
    /// The CIB, written at `cib_paddr`.
    pub cib_block: Vec<u8>,
    pub cib_paddr: u64,
    /// One bitmap-block payload per chunk, written at the matching
    /// entry of `bitmap_paddrs`.
    pub bitmap_blocks: Vec<Vec<u8>>,
    pub bitmap_paddrs: Vec<u64>,
    /// The IP-bitmap ring's first slot, written at `layout.ip_bm_base`.
    /// It has no `obj_phys_t` header. The other ring slots stay zero.
    pub ip_bm_block: Vec<u8>,
}

/// Build the spaceman_phys, the single chunk_info_block, one bitmap
/// block per chunk and the live IP-bitmap block. The caller is
/// responsible for writing each block at the address recorded in the
/// result.
pub(super) fn build_spaceman(layout: &SpacemanLayout) -> Result<EmittedSpaceman> {
    let bs = layout.block_size;
    if bs < 4096 || !bs.is_power_of_two() {
        return Err(crate::Error::Unsupported(format!(
            "apfs spaceman: block size {bs} is too small for spaceman_phys_t"
        )));
    }
    let bpc = blocks_per_chunk(bs);
    let chunks: u64 = layout.total_blocks.div_ceil(bpc);
    let cpc = chunks_per_cib(bs);
    if chunks as u32 > cpc {
        return Err(crate::Error::Unsupported(format!(
            "apfs spaceman: {chunks} chunks would overflow a single CIB \
             (max {cpc}); CAB layer not implemented"
        )));
    }
    let ip_blocks = ip_block_count(chunks);
    // One IP-bitmap block covers `8 * bs` pool blocks.
    let ip_bm_size_in_blocks = ip_blocks.div_ceil(8 * bs as u64) as u32;
    let ring = SPACEMAN_IP_BM_TX_MULTIPLIER;
    if ip_bm_size_in_blocks >= ring {
        return Err(crate::Error::Unsupported(
            "apfs spaceman: internal pool too large for the IP-bitmap ring".into(),
        ));
    }

    // Internal-pool allocations: the CIB, then one bitmap per chunk.
    let cib_paddr = layout.ip_base;
    let bitmap_paddrs: Vec<u64> = (0..chunks).map(|i| layout.ip_base + 1 + i).collect();
    let ip_used = 1 + chunks;

    // ---- Per-chunk bitmaps ------------------------------------------
    let mut bitmap_blocks: Vec<Vec<u8>> = Vec::with_capacity(chunks as usize);
    let mut free_total: u64 = 0;
    let mut free_per_chunk: Vec<u32> = Vec::with_capacity(chunks as usize);
    for chunk_idx in 0..chunks {
        let mut bmap = vec![0u8; bs];
        let chunk_start = chunk_idx * bpc;
        let chunk_end = ((chunk_idx + 1) * bpc).min(layout.total_blocks);
        let chunk_blocks = (chunk_end - chunk_start) as u32;
        // Mark every used block inside this chunk's bitmap. Bits past
        // the end of the container stay clear, as newfs_apfs leaves
        // them: `ci_block_count` already bounds the chunk.
        for &(rs, re) in &layout.used_ranges {
            let lo = rs.max(chunk_start);
            let hi = re.min(chunk_end);
            for b in lo..hi {
                let bit = (b - chunk_start) as usize;
                bmap[bit / 8] |= 1 << (bit % 8);
            }
        }
        let used: u32 = bmap.iter().map(|b| b.count_ones()).sum();
        let free = chunk_blocks - used;
        free_per_chunk.push(free);
        free_total += free as u64;
        bitmap_blocks.push(bmap);
    }

    // ---- Chunk-info-block (CIB) -------------------------------------
    let mut cib = vec![0u8; bs];
    cib[8..16].copy_from_slice(&cib_paddr.to_le_bytes());
    cib[16..24].copy_from_slice(&layout.xid.to_le_bytes());
    cib[24..28].copy_from_slice(&(OBJECT_TYPE_SPACEMAN_CIB | OBJ_PHYSICAL).to_le_bytes());
    // cib_index = 0, cib_chunk_info_count
    cib[36..40].copy_from_slice(&(chunks as u32).to_le_bytes());
    for (chunk_idx, (&free_in_chunk, &bmap_paddr)) in
        free_per_chunk.iter().zip(bitmap_paddrs.iter()).enumerate()
    {
        let off = 40 + chunk_idx * 32;
        let chunk_start = (chunk_idx as u64) * bpc;
        let chunk_end = (chunk_start + bpc).min(layout.total_blocks);
        let chunk_blocks = (chunk_end - chunk_start) as u32;
        cib[off..off + 8].copy_from_slice(&layout.xid.to_le_bytes()); // ci_xid
        cib[off + 8..off + 16].copy_from_slice(&chunk_start.to_le_bytes()); // ci_addr
        cib[off + 16..off + 20].copy_from_slice(&chunk_blocks.to_le_bytes());
        cib[off + 20..off + 24].copy_from_slice(&free_in_chunk.to_le_bytes());
        cib[off + 24..off + 32].copy_from_slice(&bmap_paddr.to_le_bytes());
    }
    sign_block(&mut cib);

    // ---- Spaceman header --------------------------------------------
    let mut sm = vec![0u8; bs];
    sm[8..16].copy_from_slice(&layout.spaceman_oid.to_le_bytes());
    sm[16..24].copy_from_slice(&layout.xid.to_le_bytes());
    sm[24..28].copy_from_slice(&(OBJECT_TYPE_SPACEMAN | OBJ_EPHEMERAL).to_le_bytes());
    sm[32..36].copy_from_slice(&(bs as u32).to_le_bytes());
    sm[36..40].copy_from_slice(&(bpc as u32).to_le_bytes());
    sm[40..44].copy_from_slice(&cpc.to_le_bytes());
    let cibs_per_cab = ((bs - 40) / 8) as u32;
    sm[44..48].copy_from_slice(&cibs_per_cab.to_le_bytes());

    // Variable-length arrays past the fixed struct, in newfs_apfs order.
    let xid_off = SM_STRUCT_SIZE;
    let bm_index_off = xid_off + 8 * ip_bm_size_in_blocks as usize;
    let free_next_off = bm_index_off + (2 * ip_bm_size_in_blocks as usize).next_multiple_of(8);
    let main_addr_off = free_next_off + (2 * ring as usize).next_multiple_of(8);
    let tier2_addr_off = main_addr_off + 8; // one CIB on the main device
    if tier2_addr_off + 8 > bs {
        return Err(crate::Error::Unsupported(
            "apfs spaceman: spaceman_phys_t arrays overflow the block".into(),
        ));
    }

    // SD_MAIN spaceman_device_t (48 bytes) at offset 48
    sm[48..56].copy_from_slice(&layout.total_blocks.to_le_bytes()); // sm_block_count
    sm[56..64].copy_from_slice(&chunks.to_le_bytes()); // sm_chunk_count
    sm[64..68].copy_from_slice(&1u32.to_le_bytes()); // sm_cib_count
    sm[68..72].copy_from_slice(&0u32.to_le_bytes()); // sm_cab_count
    sm[72..80].copy_from_slice(&free_total.to_le_bytes()); // sm_free_count
    sm[80..84].copy_from_slice(&(main_addr_off as u32).to_le_bytes()); // sm_addr_offset
    // SD_TIER2: empty device, but its address array still has a home.
    sm[128..132].copy_from_slice(&(tier2_addr_off as u32).to_le_bytes());

    sm[144..148].copy_from_slice(&SM_FLAG_VERSIONED.to_le_bytes());

    // ---- Internal pool ----------------------------------------------
    sm[148..152].copy_from_slice(&SPACEMAN_IP_BM_TX_MULTIPLIER.to_le_bytes());
    sm[152..160].copy_from_slice(&ip_blocks.to_le_bytes());
    sm[160..164].copy_from_slice(&ip_bm_size_in_blocks.to_le_bytes());
    sm[164..168].copy_from_slice(&ring.to_le_bytes()); // sm_ip_bm_block_count
    sm[168..176].copy_from_slice(&layout.ip_bm_base.to_le_bytes());
    sm[176..184].copy_from_slice(&layout.ip_base.to_le_bytes());

    // ---- Free queues ------------------------------------------------
    // spaceman_free_queue_t (40 bytes): count u64, tree_oid u64,
    // oldest_xid u64, tree_node_limit u16, pad. All empty with no
    // tree; only the node limits are set (IP: 1, tier2: 0).
    sm[200 + 24..200 + 26].copy_from_slice(&1u16.to_le_bytes());
    sm[240 + 24..240 + 26].copy_from_slice(&layout.main_fq_node_limit.max(1).to_le_bytes());

    // ---- IP-bitmap ring ---------------------------------------------
    // Slots 0..size_in_blocks hold the live bitmap(s); the rest form the
    // free list head..tail.
    sm[320..322].copy_from_slice(&(ip_bm_size_in_blocks as u16).to_le_bytes()); // free_head
    sm[322..324].copy_from_slice(&((ring - 1) as u16).to_le_bytes()); // free_tail
    sm[324..328].copy_from_slice(&(xid_off as u32).to_le_bytes());
    sm[328..332].copy_from_slice(&(bm_index_off as u32).to_le_bytes());
    sm[332..336].copy_from_slice(&(free_next_off as u32).to_le_bytes());
    sm[336..340].copy_from_slice(&1u32.to_le_bytes()); // sm_version
    sm[340..344].copy_from_slice(&(SM_STRUCT_SIZE as u32).to_le_bytes());
    for i in 0..ip_bm_size_in_blocks as usize {
        let o = xid_off + 8 * i;
        sm[o..o + 8].copy_from_slice(&layout.xid.to_le_bytes());
        let o = bm_index_off + 2 * i;
        sm[o..o + 2].copy_from_slice(&(i as u16).to_le_bytes());
    }
    for slot in 0..ring {
        let next = if slot < ip_bm_size_in_blocks || slot == ring - 1 {
            SPACEMAN_IP_BM_INDEX_INVALID
        } else {
            (slot + 1) as u16
        };
        let o = free_next_off + 2 * slot as usize;
        sm[o..o + 2].copy_from_slice(&next.to_le_bytes());
    }

    // Main-device CIB address array.
    sm[main_addr_off..main_addr_off + 8].copy_from_slice(&cib_paddr.to_le_bytes());

    sign_block(&mut sm);

    // ---- IP bitmap block --------------------------------------------
    // Bit i set = pool block `ip_base + i` in use. No obj_phys_t.
    let mut ip_bm_block = vec![0u8; bs];
    for bit in 0..ip_used as usize {
        ip_bm_block[bit / 8] |= 1 << (bit % 8);
    }

    Ok(EmittedSpaceman {
        spaceman_block: sm,
        cib_block: cib,
        cib_paddr,
        bitmap_blocks,
        bitmap_paddrs,
        ip_bm_block,
    })
}

/// Fletcher-64 sign helper (duplicated from `write.rs` so this module
/// is self-contained).
fn sign_block(buf: &mut [u8]) {
    let cksum = fletcher64(buf);
    buf[0..8].copy_from_slice(&cksum.to_le_bytes());
}

// ---- decoders for tests ----

/// Lightweight decoded view of a spaceman header used by lib tests.
#[cfg(test)]
#[derive(Debug)]
pub(super) struct DecodedSpaceman {
    pub block_size: u32,
    pub blocks_per_chunk: u32,
    pub main_block_count: u64,
    pub main_chunk_count: u64,
    pub main_cib_count: u32,
    pub main_cab_count: u32,
    pub main_free_count: u64,
    pub cib_paddr: u64,
    pub flags: u32,
    pub ip_bm_tx_multiplier: u32,
    pub ip_block_count: u64,
    pub ip_bm_size_in_blocks: u32,
    pub ip_bm_block_count: u32,
    pub ip_bm_base: u64,
    pub ip_base: u64,
    pub sfq_tree_oids: [u64; 3],
    pub sfq_node_limits: [u16; 3],
    pub datazone_main_zone0_start: u64,
    pub datazone_main_zone0_end: u64,
}

/// Decode a freshly emitted spaceman block. Returns an error if the
/// type bits or version look wrong.
#[cfg(test)]
pub(super) fn decode_spaceman(buf: &[u8]) -> Result<DecodedSpaceman> {
    if buf.len() < SM_DATAZONE_OFFSET + DATAZONE_SIZE {
        return Err(crate::Error::InvalidImage(
            "apfs spaceman: block too short".into(),
        ));
    }
    let otype = u32::from_le_bytes(buf[24..28].try_into().unwrap());
    if otype & 0x0000_ffff != OBJECT_TYPE_SPACEMAN {
        return Err(crate::Error::InvalidImage(format!(
            "apfs spaceman: unexpected object type {otype:#x}"
        )));
    }
    let block_size = u32::from_le_bytes(buf[32..36].try_into().unwrap());
    let blocks_per_chunk = u32::from_le_bytes(buf[36..40].try_into().unwrap());
    let main_block_count = u64::from_le_bytes(buf[48..56].try_into().unwrap());
    let main_chunk_count = u64::from_le_bytes(buf[56..64].try_into().unwrap());
    let main_cib_count = u32::from_le_bytes(buf[64..68].try_into().unwrap());
    let main_cab_count = u32::from_le_bytes(buf[68..72].try_into().unwrap());
    let main_free_count = u64::from_le_bytes(buf[72..80].try_into().unwrap());
    let cib_addr_off = u32::from_le_bytes(buf[80..84].try_into().unwrap()) as usize;
    if cib_addr_off + 8 > buf.len() {
        return Err(crate::Error::InvalidImage(format!(
            "apfs spaceman: sm_addr_offset {cib_addr_off} past block end"
        )));
    }
    let cib_paddr = u64::from_le_bytes(buf[cib_addr_off..cib_addr_off + 8].try_into().unwrap());
    let flags = u32::from_le_bytes(buf[144..148].try_into().unwrap());
    let ip_bm_tx_multiplier = u32::from_le_bytes(buf[148..152].try_into().unwrap());
    let ip_block_count = u64::from_le_bytes(buf[152..160].try_into().unwrap());
    let ip_bm_size_in_blocks = u32::from_le_bytes(buf[160..164].try_into().unwrap());
    let ip_bm_block_count = u32::from_le_bytes(buf[164..168].try_into().unwrap());
    let ip_bm_base = u64::from_le_bytes(buf[168..176].try_into().unwrap());
    let ip_base = u64::from_le_bytes(buf[176..184].try_into().unwrap());
    let mut sfq_tree_oids = [0u64; 3];
    let mut sfq_node_limits = [0u16; 3];
    for i in 0..3 {
        let off = 200 + i * 40;
        sfq_tree_oids[i] = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap());
        sfq_node_limits[i] = u16::from_le_bytes(buf[off + 24..off + 26].try_into().unwrap());
    }
    let dz_main_zone0 =
        SM_DATAZONE_OFFSET + (SD_MAIN * SM_DATAZONE_ALLOCZONE_COUNT) * ALLOC_ZONE_INFO_SIZE;
    let datazone_main_zone0_start =
        u64::from_le_bytes(buf[dz_main_zone0..dz_main_zone0 + 8].try_into().unwrap());
    let datazone_main_zone0_end = u64::from_le_bytes(
        buf[dz_main_zone0 + 8..dz_main_zone0 + 16]
            .try_into()
            .unwrap(),
    );
    Ok(DecodedSpaceman {
        block_size,
        blocks_per_chunk,
        main_block_count,
        main_chunk_count,
        main_cib_count,
        main_cab_count,
        main_free_count,
        cib_paddr,
        flags,
        ip_bm_tx_multiplier,
        ip_block_count,
        ip_bm_size_in_blocks,
        ip_bm_block_count,
        ip_bm_base,
        ip_base,
        sfq_tree_oids,
        sfq_node_limits,
        datazone_main_zone0_start,
        datazone_main_zone0_end,
    })
}

/// Decode the chunk_info entries inside a CIB block.
#[cfg(test)]
pub(super) fn decode_cib_entries(buf: &[u8]) -> Result<Vec<DecodedChunkInfo>> {
    if buf.len() < 40 {
        return Err(crate::Error::InvalidImage(
            "apfs CIB: block too short".into(),
        ));
    }
    let otype = u32::from_le_bytes(buf[24..28].try_into().unwrap());
    if otype & 0x0000_ffff != OBJECT_TYPE_SPACEMAN_CIB {
        return Err(crate::Error::InvalidImage(format!(
            "apfs CIB: unexpected object type {otype:#x}"
        )));
    }
    let count = u32::from_le_bytes(buf[36..40].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = 40 + i * 32;
        if off + 32 > buf.len() {
            return Err(crate::Error::InvalidImage(
                "apfs CIB: chunk_info_t past block end".into(),
            ));
        }
        out.push(DecodedChunkInfo {
            addr: u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap()),
            block_count: u32::from_le_bytes(buf[off + 16..off + 20].try_into().unwrap()),
            free_count: u32::from_le_bytes(buf[off + 20..off + 24].try_into().unwrap()),
            bitmap_addr: u64::from_le_bytes(buf[off + 24..off + 32].try_into().unwrap()),
        });
    }
    Ok(out)
}

/// Lightweight decoded view of one `chunk_info_t`.
#[cfg(test)]
#[derive(Debug)]
pub(super) struct DecodedChunkInfo {
    pub addr: u64,
    pub block_count: u32,
    pub free_count: u32,
    pub bitmap_addr: u64,
}

/// Count the set bits in a bitmap buffer covering the first
/// `chunk_blocks` bits. (Bits past `chunk_blocks` are ignored.)
#[cfg(test)]
pub(super) fn count_used_bits(bmap: &[u8], chunk_blocks: u32) -> u32 {
    let mut n: u32 = 0;
    for bit in 0..chunk_blocks as usize {
        if bmap[bit / 8] & (1 << (bit % 8)) != 0 {
            n += 1;
        }
    }
    n
}
