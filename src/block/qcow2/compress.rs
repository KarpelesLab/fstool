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
