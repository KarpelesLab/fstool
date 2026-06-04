//! qcow2 cluster compression codecs.
//!
//! qcow2 stores each compressed cluster as a self-contained stream:
//! `compression_type = 0` is **raw DEFLATE** (RFC 1951, no zlib/gzip framing)
//! and `compression_type = 1` is a **zstd** frame. qemu compresses (and
//! decompresses) deflate clusters with a 4 KiB sliding window
//! (`deflateInit2(.., -12, ..)` / `inflateInit2(.., -12)`), so the encoder
//! must cap its match distance at 4096 to stay readable by qemu, and the
//! decoder only needs a 4 KiB window — which also bounds per-cluster RAM.
//!
//! The codecs are feature-gated (`gzip` → deflate, `zstd` → zstd); a build
//! without them returns a clean `Unsupported` rather than failing to compile.

use crate::{Error, Result};

/// qcow2 `compression_type` values.
pub const CTYPE_ZLIB: u8 = 0;
pub const CTYPE_ZSTD: u8 = 1;

/// The 4 KiB window qemu uses for qcow2 deflate clusters.
#[cfg(feature = "gzip")]
pub const QCOW2_DEFLATE_WINDOW: usize = 4096;

/// Decompress one compressed cluster's bytes into at most `cluster_size`
/// output bytes. `src` is exactly the compressed payload (`byte_len` bytes
/// read from the host offset). The result is the decoded cluster, which the
/// caller treats as `cluster_size` bytes (shorter output is zero-padded by
/// the caller — qcow2 always compresses full clusters).
pub fn decompress_cluster(ctype: u8, src: &[u8], cluster_size: usize) -> Result<Vec<u8>> {
    match ctype {
        CTYPE_ZLIB => inflate_deflate(src, cluster_size),
        CTYPE_ZSTD => inflate_zstd(src, cluster_size),
        other => Err(Error::Unsupported(format!(
            "qcow2: unknown compression_type {other}"
        ))),
    }
}

// ───────────────────────── bounded decode loop ─────────────────────────

/// Drive a compcol decoder over one compressed cluster, stopping at the first
/// of: a full `cluster_size` of output (the authoritative end — qcow2 always
/// compresses whole clusters), the codec's stream-end, or input exhaustion.
///
/// This is essential because the L2 sector count rounds the stored length up
/// to a 512-byte boundary, so the payload is **zero-padded past the real
/// stream**. Feeding that padding back to the decoder would look like extra
/// (garbage) blocks/frames and could spin or error — so we never do.
#[cfg(any(feature = "gzip", feature = "zstd"))]
fn decode_bounded<D: compcol::Decoder>(
    mut dec: D,
    src: &[u8],
    cluster_size: usize,
) -> Result<Vec<u8>> {
    use compcol::Status;
    let mut out = Vec::with_capacity(cluster_size);
    let mut scratch = vec![0u8; cluster_size.max(4096)];
    let mut consumed = 0usize;
    loop {
        let (p, status) = dec
            .decode(&src[consumed..], &mut scratch)
            .map_err(|e| Error::InvalidImage(format!("qcow2: cluster decode failed: {e}")))?;
        out.extend_from_slice(&scratch[..p.written]);
        consumed += p.consumed;
        if out.len() >= cluster_size {
            out.truncate(cluster_size);
            return Ok(out);
        }
        match status {
            Status::StreamEnd => return Ok(out),
            Status::InputEmpty => break,
            // No forward progress with input still present → the stream ended
            // and the remainder is padding; stop rather than spin.
            Status::OutputFull if p.written == 0 && p.consumed == 0 => break,
            Status::OutputFull => continue,
        }
    }
    loop {
        let (p, status) = dec
            .finish(&mut scratch)
            .map_err(|e| Error::InvalidImage(format!("qcow2: cluster decode failed: {e}")))?;
        out.extend_from_slice(&scratch[..p.written]);
        if out.len() >= cluster_size {
            out.truncate(cluster_size);
            return Ok(out);
        }
        if matches!(status, Status::StreamEnd) || p.written == 0 {
            break;
        }
    }
    Ok(out)
}

// ───────────────────────────── deflate ─────────────────────────────

#[cfg(feature = "gzip")]
fn inflate_deflate(src: &[u8], cluster_size: usize) -> Result<Vec<u8>> {
    use compcol::Algorithm;
    let cfg = compcol::deflate::DecoderConfig::default().with_window_size(QCOW2_DEFLATE_WINDOW);
    decode_bounded(
        compcol::deflate::Deflate::decoder_with(cfg),
        src,
        cluster_size,
    )
}

#[cfg(not(feature = "gzip"))]
fn inflate_deflate(_src: &[u8], _cluster_size: usize) -> Result<Vec<u8>> {
    Err(Error::Unsupported(
        "qcow2: zlib/deflate-compressed clusters need the `gzip` feature".into(),
    ))
}

// ────────────────────────────── zstd ──────────────────────────────

#[cfg(feature = "zstd")]
fn inflate_zstd(src: &[u8], cluster_size: usize) -> Result<Vec<u8>> {
    use compcol::Algorithm;
    decode_bounded(compcol::zstd::Zstd::decoder(), src, cluster_size)
}

#[cfg(not(feature = "zstd"))]
fn inflate_zstd(_src: &[u8], _cluster_size: usize) -> Result<Vec<u8>> {
    Err(Error::Unsupported(
        "qcow2: zstd-compressed clusters need the `zstd` feature".into(),
    ))
}

// ───────────────────────── compressed writer ─────────────────────────

/// Drive a compcol encoder over a whole cluster, returning the compressed
/// bytes. Encoding always terminates (finite input).
#[cfg(any(feature = "gzip", feature = "zstd"))]
fn encode_all<E: compcol::Encoder>(mut enc: E, plain: &[u8]) -> Result<Vec<u8>> {
    use compcol::Status;
    let mut out = Vec::with_capacity(plain.len() / 2 + 64);
    let mut scratch = vec![0u8; 64 * 1024];
    let mut consumed = 0usize;
    loop {
        let (p, status) = enc
            .encode(&plain[consumed..], &mut scratch)
            .map_err(|e| Error::Io(std::io::Error::other(format!("qcow2: encode failed: {e}"))))?;
        out.extend_from_slice(&scratch[..p.written]);
        consumed += p.consumed;
        match status {
            Status::StreamEnd => return Ok(out),
            Status::InputEmpty => break,
            Status::OutputFull => continue,
        }
    }
    loop {
        let (p, status) = enc
            .finish(&mut scratch)
            .map_err(|e| Error::Io(std::io::Error::other(format!("qcow2: encode failed: {e}"))))?;
        out.extend_from_slice(&scratch[..p.written]);
        if matches!(status, Status::StreamEnd) || p.written == 0 {
            break;
        }
    }
    Ok(out)
}

/// Compress one full cluster with the chosen codec. Deflate uses the 4 KiB
/// window qemu's inflate requires; zstd uses its default frame.
pub fn compress_cluster(ctype: u8, plain: &[u8], level: u8) -> Result<Vec<u8>> {
    match ctype {
        CTYPE_ZLIB => deflate_encode(plain, level),
        CTYPE_ZSTD => zstd_encode(plain),
        other => Err(Error::Unsupported(format!(
            "qcow2: unknown compression_type {other}"
        ))),
    }
}

#[cfg(feature = "gzip")]
fn deflate_encode(plain: &[u8], level: u8) -> Result<Vec<u8>> {
    use compcol::Algorithm;
    let cfg = compcol::deflate::EncoderConfig::default()
        .with_level(level.clamp(1, 9))
        .with_max_distance(QCOW2_DEFLATE_WINDOW);
    encode_all(compcol::deflate::Deflate::encoder_with(cfg), plain)
}

#[cfg(not(feature = "gzip"))]
fn deflate_encode(_plain: &[u8], _level: u8) -> Result<Vec<u8>> {
    Err(Error::Unsupported(
        "qcow2: writing zlib-compressed clusters needs the `gzip` feature".into(),
    ))
}

#[cfg(feature = "zstd")]
fn zstd_encode(plain: &[u8]) -> Result<Vec<u8>> {
    use compcol::Algorithm;
    encode_all(compcol::zstd::Zstd::encoder(), plain)
}

#[cfg(not(feature = "zstd"))]
fn zstd_encode(_plain: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Unsupported(
        "qcow2: writing zstd-compressed clusters needs the `zstd` feature".into(),
    ))
}

/// Serialise the whole virtual disk read from `src` into a fresh
/// **compressed** qcow2 v3 image at `path`. Each non-zero cluster is
/// compressed once (all-zero clusters stay unallocated, so the output is
/// sparse); the compressed payloads are packed byte-granularly and the L1/L2
/// tables, refcount table/blocks, and header are built to match — including
/// exact refcounts for host clusters shared between adjacent compressed
/// clusters, so `qemu-img check` is clean. Returns the output file size.
pub fn write_compressed_image(
    src: &mut dyn crate::block::BlockDevice,
    path: &std::path::Path,
    cluster_size: u32,
    ctype: u8,
    level: u8,
) -> Result<u64> {
    use super::header::{self, Header};
    use super::l1l2::{COMPRESSED, COPIED};
    use std::io::{Seek, SeekFrom, Write};

    if !cluster_size.is_power_of_two() || cluster_size < 512 {
        return Err(Error::InvalidArgument(format!(
            "qcow2: cluster_size {cluster_size} must be a power of two ≥ 512"
        )));
    }
    let cs = cluster_size as u64;
    let cluster_bits = cs.trailing_zeros();
    let virtual_size = src.total_size();
    let l2_entries = cs / 8;
    let epb = cs / 2; // refcount entries per block (16-bit)
    let x = 62 - (cluster_bits - 8); // host-offset bit width in a compressed L2 entry

    // L1 sizing (whole clusters), matching Qcow2Backend::create.
    let l2_coverage = l2_entries * cs;
    let mut l1_size = virtual_size.div_ceil(l2_coverage);
    let l1_per_cluster = cs / 8;
    let l1_clusters = l1_size.div_ceil(l1_per_cluster).max(1);
    l1_size = l1_clusters * l1_per_cluster;

    // Pass 1: compress every non-zero cluster.
    struct Comp {
        vcluster: u64,
        bytes: Vec<u8>,
    }
    let mut comps: Vec<Comp> = Vec::new();
    let mut cluster_buf = vec![0u8; cs as usize];
    let total_vclusters = virtual_size.div_ceil(cs);
    for vc in 0..total_vclusters {
        let off = vc * cs;
        let n = (cs.min(virtual_size - off)) as usize;
        cluster_buf[..n].fill(0);
        src.read_at(off, &mut cluster_buf[..n])?;
        if n < cs as usize {
            cluster_buf[n..].fill(0);
        }
        if cluster_buf.iter().all(|&b| b == 0) {
            continue; // sparse: leave unallocated
        }
        comps.push(Comp {
            vcluster: vc,
            bytes: compress_cluster(ctype, &cluster_buf, level)?,
        });
    }

    // Which L1 entries are used → that many L2 tables.
    let mut used_l1: Vec<u64> = comps.iter().map(|c| c.vcluster / l2_entries).collect();
    used_l1.sort_unstable();
    used_l1.dedup();
    let n_l2 = used_l1.len() as u64;

    // Layout (clusters): 0 header, 1 refcount table, then refcount blocks,
    // L1, L2 tables, and finally the packed compressed data. The refcount
    // block count depends on the total cluster count, so converge it.
    let data_bytes: u64 = comps.iter().map(|c| c.bytes.len() as u64).sum();
    let data_clusters = data_bytes.div_ceil(cs);
    let fixed = 2 + l1_clusters + n_l2; // header + rct + L1 + L2s
    let mut rcb_count = 1u64;
    loop {
        let total = fixed + rcb_count + data_clusters;
        let need = total.div_ceil(epb).max(1);
        if need == rcb_count {
            break;
        }
        rcb_count = need;
    }
    if rcb_count > l1_per_cluster {
        return Err(Error::Unsupported(
            "qcow2: compressed image needs a multi-cluster refcount table (not implemented)".into(),
        ));
    }

    let rct_cluster = 1u64;
    let rcb_start = 2u64;
    let l1_start = rcb_start + rcb_count;
    let l2_start = l1_start + l1_clusters;
    let data_start_cluster = l2_start + n_l2;
    let data_start_byte = data_start_cluster * cs;

    // Pack compressed payloads byte-granularly and build the L2 tables.
    // l1_index → its L2 cluster offset.
    let mut l2_cluster_of: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    for (i, &l1i) in used_l1.iter().enumerate() {
        l2_cluster_of.insert(l1i, l2_start + i as u64);
    }
    let mut l2_tables: std::collections::HashMap<u64, Vec<u64>> = std::collections::HashMap::new();
    let mut refcount: std::collections::HashMap<u64, u16> = std::collections::HashMap::new();
    let bump = |m: &mut std::collections::HashMap<u64, u16>, c: u64| {
        *m.entry(c).or_insert(0) += 1;
    };
    // Metadata clusters: refcount 1.
    bump(&mut refcount, 0); // header
    bump(&mut refcount, rct_cluster);
    for c in rcb_start..rcb_start + rcb_count {
        bump(&mut refcount, c);
    }
    for c in l1_start..l1_start + l1_clusters {
        bump(&mut refcount, c);
    }
    for c in l2_start..l2_start + n_l2 {
        bump(&mut refcount, c);
    }

    let mut packed: Vec<(u64, &[u8])> = Vec::with_capacity(comps.len()); // (host_offset, bytes)
    let mut running = data_start_byte;
    for c in &comps {
        let host_offset = running;
        let len = c.bytes.len() as u64;
        if len == 0 {
            // A codec must never return an empty stream for a non-empty
            // cluster; bail loudly rather than underflow the sector math.
            return Err(Error::Io(std::io::Error::other(
                "qcow2: compressor produced an empty cluster",
            )));
        }
        running += len;
        // L2 compressed entry: COMPRESSED | host_offset | ((nb_sectors-1) << x).
        let first_sec = host_offset / 512;
        let last_sec = (host_offset + len - 1) / 512;
        let nb_sectors = last_sec - first_sec + 1;
        let entry = COMPRESSED | host_offset | ((nb_sectors - 1) << x);
        let l1i = c.vcluster / l2_entries;
        let l2 = l2_tables
            .entry(l1i)
            .or_insert_with(|| vec![0u64; l2_entries as usize]);
        l2[(c.vcluster % l2_entries) as usize] = entry;
        // Each host cluster the payload touches gains one reference (adjacent
        // compressed clusters can share a boundary cluster → refcount > 1).
        for hcluster in (host_offset / cs)..=((host_offset + len - 1) / cs) {
            bump(&mut refcount, hcluster);
        }
        packed.push((host_offset, &c.bytes));
    }
    let file_len = running.div_ceil(cs).max(data_start_cluster) * cs;

    // Build the L1 table.
    let mut l1 = vec![0u64; l1_size as usize];
    for (&l1i, &l2c) in &l2_cluster_of {
        l1[l1i as usize] = (l2c * cs) | COPIED;
    }

    // Build refcount blocks + table.
    let max_cluster = (file_len / cs).saturating_sub(1);
    let needed_blocks = (max_cluster / epb + 1).max(rcb_count);
    if needed_blocks > l1_per_cluster {
        // The refcount table would need more than one cluster — not supported
        // (matches Qcow2Backend::create's single-table-cluster assumption).
        return Err(Error::Unsupported(
            "qcow2: compressed image too large for a single-cluster refcount table".into(),
        ));
    }
    let mut rcb: Vec<Vec<u16>> = (0..needed_blocks)
        .map(|_| vec![0u16; epb as usize])
        .collect();
    for (&cluster, &cnt) in &refcount {
        let b = (cluster / epb) as usize;
        rcb[b][(cluster % epb) as usize] = cnt;
    }
    let mut rct = vec![0u64; l1_per_cluster as usize];
    for (b, _) in rcb.iter().enumerate() {
        rct[b] = (rcb_start + b as u64) * cs;
    }

    // Header.
    let header = Header {
        version: header::VERSION_V3,
        backing_file_offset: 0,
        backing_file_size: 0,
        cluster_bits,
        size: virtual_size,
        crypt_method: 0,
        l1_size: l1_size as u32,
        l1_table_offset: l1_start * cs,
        refcount_table_offset: rct_cluster * cs,
        refcount_table_clusters: 1,
        nb_snapshots: 0,
        snapshots_offset: 0,
        incompatible_features: if ctype != CTYPE_ZLIB {
            super::header::incompat::COMPRESSION_TYPE
        } else {
            0
        },
        compatible_features: 0,
        autoclear_features: 0,
        refcount_order: 4,
        header_length: if ctype != CTYPE_ZLIB { 112 } else { 104 },
        compression_type: ctype,
    };

    // Write it all.
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    f.set_len(file_len)?;

    let mut header_cluster = vec![0u8; cs as usize];
    header_cluster[..header::V3_HEADER_LEN].copy_from_slice(&header.encode_v3());
    if ctype != CTYPE_ZLIB {
        header_cluster[100..104].copy_from_slice(&112u32.to_be_bytes());
        header_cluster[104] = ctype;
    }
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&header_cluster)?;

    let mut rct_bytes = vec![0u8; cs as usize];
    for (i, &e) in rct.iter().enumerate() {
        rct_bytes[i * 8..i * 8 + 8].copy_from_slice(&e.to_be_bytes());
    }
    f.seek(SeekFrom::Start(rct_cluster * cs))?;
    f.write_all(&rct_bytes)?;

    for (b, block) in rcb.iter().enumerate() {
        let mut raw = vec![0u8; cs as usize];
        for (i, &e) in block.iter().enumerate() {
            raw[i * 2..i * 2 + 2].copy_from_slice(&e.to_be_bytes());
        }
        f.seek(SeekFrom::Start((rcb_start + b as u64) * cs))?;
        f.write_all(&raw)?;
    }

    let mut l1_bytes = vec![0u8; (l1_size * 8) as usize];
    for (i, &e) in l1.iter().enumerate() {
        l1_bytes[i * 8..i * 8 + 8].copy_from_slice(&e.to_be_bytes());
    }
    f.seek(SeekFrom::Start(l1_start * cs))?;
    f.write_all(&l1_bytes)?;

    for (&l1i, table) in &l2_tables {
        let l2c = l2_cluster_of[&l1i];
        let mut raw = vec![0u8; cs as usize];
        for (i, &e) in table.iter().enumerate() {
            raw[i * 8..i * 8 + 8].copy_from_slice(&e.to_be_bytes());
        }
        f.seek(SeekFrom::Start(l2c * cs))?;
        f.write_all(&raw)?;
    }

    for (host_offset, bytes) in &packed {
        f.seek(SeekFrom::Start(*host_offset))?;
        f.write_all(bytes)?;
    }
    f.sync_data()?;
    Ok(file_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "gzip")]
    #[test]
    fn deflate_cluster_round_trip_4k_window() {
        // Encode with the 4 KiB-window encoder (qemu-compatible) and decode.
        use compcol::{Algorithm, Encoder};
        let cluster: Vec<u8> = (0..65536u32).map(|i| (i * 31 % 256) as u8).collect();
        let cfg = compcol::deflate::EncoderConfig::default()
            .with_level(6)
            .with_max_distance(QCOW2_DEFLATE_WINDOW);
        let mut enc = compcol::deflate::Deflate::encoder_with(cfg);
        let mut comp = Vec::new();
        let mut scratch = vec![0u8; 64 * 1024];
        let mut consumed = 0;
        loop {
            let (p, status) = enc.encode(&cluster[consumed..], &mut scratch).unwrap();
            comp.extend_from_slice(&scratch[..p.written]);
            consumed += p.consumed;
            if matches!(status, compcol::Status::InputEmpty) && consumed >= cluster.len() {
                break;
            }
        }
        loop {
            let (p, status) = enc.finish(&mut scratch).unwrap();
            comp.extend_from_slice(&scratch[..p.written]);
            if matches!(status, compcol::Status::StreamEnd) || p.written == 0 {
                break;
            }
        }
        let out = decompress_cluster(CTYPE_ZLIB, &comp, cluster.len()).unwrap();
        assert_eq!(out, cluster);
    }
}
