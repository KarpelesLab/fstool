//! The Apple Partition Map in the system area, the way
//! `hdiutil makehybrid` writes it: a Driver Descriptor Map advertising
//! 2048-byte blocks, then 512-byte map entries — the map itself and one
//! `Apple_HFS` partition — all addressed in 512-byte units.

/// Bytes the map occupies (DDM + two entries).
pub(crate) const APM_BYTES: u64 = 3 * 512;

/// Entries the map partition reserves room for (blocks 1..=63), as
/// makehybrid does. Ends at byte 32 KiB, the end of the system area.
const MAP_BLOCKS: u32 = 63;

fn entry(
    map_entries: u32,
    start: u32,
    count: u32,
    name: &str,
    kind: &str,
    status: u32,
) -> [u8; 512] {
    let mut e = [0u8; 512];
    e[0..2].copy_from_slice(b"PM");
    e[4..8].copy_from_slice(&map_entries.to_be_bytes());
    e[8..12].copy_from_slice(&start.to_be_bytes());
    e[12..16].copy_from_slice(&count.to_be_bytes());
    let n = name.as_bytes();
    e[16..16 + n.len().min(32)].copy_from_slice(&n[..n.len().min(32)]);
    let k = kind.as_bytes();
    e[48..48 + k.len().min(32)].copy_from_slice(&k[..k.len().min(32)]);
    e[80..84].copy_from_slice(&0u32.to_be_bytes()); // pmLgDataStart
    e[84..88].copy_from_slice(&count.to_be_bytes()); // pmDataCnt
    e[88..92].copy_from_slice(&status.to_be_bytes());
    e
}

/// The map for an image of `total_sectors` 2048-byte sectors whose HFS+
/// partition spans sectors `hfs_start .. hfs_start + hfs_sectors`.
pub(crate) fn encode(total_sectors: u32, hfs_start: u32, hfs_sectors: u32, name: &str) -> Vec<u8> {
    let mut out = vec![0u8; APM_BYTES as usize];
    out[0..2].copy_from_slice(b"ER");
    out[2..4].copy_from_slice(&2048u16.to_be_bytes());
    out[4..8].copy_from_slice(&total_sectors.to_be_bytes());
    out[512..1024].copy_from_slice(&entry(
        2,
        1,
        MAP_BLOCKS,
        "Apple",
        "Apple_partition_map",
        0x0000_0003,
    ));
    // valid | allocated | in use | readable | writable | auto-mount bits,
    // as makehybrid sets them.
    out[1024..1536].copy_from_slice(&entry(
        2,
        hfs_start * 4,
        hfs_sectors * 4,
        name,
        "Apple_HFS",
        0x4000_0077,
    ));
    out
}
