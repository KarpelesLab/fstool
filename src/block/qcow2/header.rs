//! qcow2 header — v2 and v3.
//!
//! The header is the first cluster of a qcow2 file. All multi-byte fields
//! are **big-endian** (unlike everything else in fstool).
//!
//! Layout:
//!
//! ```text
//!     0   4  magic                       "QFI\xfb"
//!     4   4  version                     2 or 3
//!     8   8  backing_file_offset         byte offset of the backing filename
//!    16   4  backing_file_size           its length in bytes (no NUL)
//!    20   4  cluster_bits                e.g. 16 → 64 KiB clusters
//!    24   8  size                        virtual size in bytes
//!    32   4  crypt_method                0 none / 1 legacy AES / 2 LUKS
//!    36   4  l1_size                     entries in the L1 table
//!    40   8  l1_table_offset             byte offset of the L1 table
//!    48   8  refcount_table_offset       byte offset of the refcount table
//!    56   4  refcount_table_clusters     number of clusters in refcount table
//!    60   4  nb_snapshots                0 (we don't support snapshots)
//!    64   8  snapshots_offset            0
//!    --- v3-only below ---
//!    72   8  incompatible_features       must be 0 for us
//!    80   8  compatible_features         informational
//!    88   8  autoclear_features          we leave as-is
//!    96   4  refcount_order              we only support 4 (16-bit refcounts)
//!   100   4  header_length               ≥ 104 for v3
//! ```
//!
//! ## Header extensions
//!
//! Everything between `header_length` and the end of the first cluster is
//! a chain of optional extensions, each `u32` type + `u32` length + data
//! padded to a multiple of 8. A type-0 record ends the chain. The two that
//! matter here are `0xE2792ACA` (the backing file's *format* name, so a
//! raw backing file is not mistaken for a qcow2) and `0x0537BE77` (where
//! the embedded LUKS header lives, for `crypt_method = 2`). Unknown
//! extensions are carried through untouched — the spec requires readers to
//! ignore what they do not recognise.

use std::io::Read;

use crate::Result;

pub const MAGIC: [u8; 4] = *b"QFI\xfb";
pub const VERSION_V2: u32 = 2;
pub const VERSION_V3: u32 = 3;
pub const V2_HEADER_LEN: usize = 72;
pub const V3_HEADER_LEN: usize = 104;

/// Header-extension type tags (qcow2 spec §"Header extensions").
pub mod ext_type {
    /// Terminates the extension chain.
    pub const END: u32 = 0x0000_0000;
    /// Backing file format name, e.g. `"raw"` or `"qcow2"`.
    pub const BACKING_FORMAT: u32 = 0xE279_2ACA;
    /// Human-readable names for the feature bits.
    pub const FEATURE_NAME_TABLE: u32 = 0x6803_F857;
    /// Bitmaps directory.
    pub const BITMAPS: u32 = 0x2385_2875;
    /// Full-disk-encryption header pointer: two big-endian u64s, the
    /// offset and length of the embedded LUKS header.
    pub const CRYPTO_HEADER: u32 = 0x0537_BE77;
    /// External data file name.
    pub const EXTERNAL_DATA_FILE: u32 = 0x4441_5441;
}

/// One header extension, kept verbatim so extensions we do not interpret
/// survive a rewrite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub kind: u32,
    pub data: Vec<u8>,
}

impl Extension {
    /// The payload as a UTF-8 string, for the name-carrying extensions.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.data).ok()
    }
}

/// Parse the extension chain that starts at `start` and may run to `end`.
///
/// Stops at the first `END` record, at `end`, or at the first malformed
/// record — a truncated tail is treated as "no more extensions" rather
/// than an error, because qemu itself tolerates trailing junk in the
/// header cluster.
pub fn parse_extensions(buf: &[u8], start: usize, end: usize) -> Vec<Extension> {
    let mut out = Vec::new();
    let mut pos = start;
    let end = end.min(buf.len());
    while pos + 8 <= end {
        let kind = u32_be(buf, pos);
        let len = u32_be(buf, pos + 4) as usize;
        if kind == ext_type::END {
            break;
        }
        let body = pos + 8;
        // Each record's payload is padded out to a multiple of 8.
        let padded = len.next_multiple_of(8);
        if body + len > end || body.checked_add(padded).is_none() {
            break;
        }
        out.push(Extension {
            kind,
            data: buf[body..body + len].to_vec(),
        });
        pos = body + padded;
    }
    out
}

/// Serialise an extension chain, terminated by an `END` record.
pub fn encode_extensions(exts: &[Extension]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in exts {
        out.extend_from_slice(&e.kind.to_be_bytes());
        out.extend_from_slice(&(e.data.len() as u32).to_be_bytes());
        out.extend_from_slice(&e.data);
        // Pad the payload to an 8-byte boundary.
        out.resize(out.len().next_multiple_of(8), 0);
    }
    out.extend_from_slice(&ext_type::END.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

/// `crypt_method` values.
pub mod crypt {
    /// Plaintext image.
    pub const NONE: u32 = 0;
    /// The legacy AES-CBC scheme. qemu still reads these but has refused
    /// to create them since 2.9.
    pub const AES: u32 = 1;
    /// LUKS, with the header embedded in the image and located by the
    /// [`CRYPTO_HEADER`](super::ext_type::CRYPTO_HEADER) extension.
    pub const LUKS: u32 = 2;
}

/// v3 incompatible-feature bits that we DON'T implement. If any are set
/// in an opened image, we error with `Unsupported`.
pub mod incompat {
    pub const DIRTY: u64 = 1 << 0;
    pub const CORRUPT: u64 = 1 << 1;
    pub const EXTERNAL_DATA_FILE: u64 = 1 << 2;
    pub const COMPRESSION_TYPE: u64 = 1 << 3;
    pub const EXTENDED_L2: u64 = 1 << 4;
}

/// Decoded qcow2 header. Always normalised to v3-shaped fields — for
/// v2 inputs the v3-only values are filled in with their v2-equivalent
/// defaults (`incompatible_features = 0`, `refcount_order = 4`).
#[derive(Debug, Clone)]
pub struct Header {
    pub version: u32,
    pub backing_file_offset: u64,
    pub backing_file_size: u32,
    pub cluster_bits: u32,
    pub size: u64,
    pub crypt_method: u32,
    pub l1_size: u32,
    pub l1_table_offset: u64,
    pub refcount_table_offset: u64,
    pub refcount_table_clusters: u32,
    pub nb_snapshots: u32,
    pub snapshots_offset: u64,
    pub incompatible_features: u64,
    pub compatible_features: u64,
    pub autoclear_features: u64,
    pub refcount_order: u32,
    pub header_length: u32,
    /// Cluster compression codec: `0` = zlib/deflate (default), `1` = zstd.
    /// Only meaningful when some cluster is compressed; the
    /// `COMPRESSION_TYPE` incompatible bit is set iff this is non-zero.
    pub compression_type: u8,
    /// Header extensions, in the order they appeared. Kept verbatim so a
    /// rewrite preserves the ones we do not interpret.
    pub extensions: Vec<Extension>,
}

impl Header {
    /// Cluster size in bytes (`1 << cluster_bits`).
    pub fn cluster_size(&self) -> u64 {
        1u64 << self.cluster_bits
    }

    /// Number of L2 entries per L2 cluster (`cluster_size / 8`).
    pub fn l2_entries_per_cluster(&self) -> u64 {
        self.cluster_size() / 8
    }

    /// Decode from a byte buffer. The buffer must contain at least the
    /// fixed-length v2 or v3 header — extra trailing bytes (extensions,
    /// padding) are ignored.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < V2_HEADER_LEN {
            return Err(crate::Error::InvalidImage(format!(
                "qcow2: header buffer is {} bytes, need ≥ {V2_HEADER_LEN}",
                buf.len()
            )));
        }
        if buf[0..4] != MAGIC {
            return Err(crate::Error::InvalidImage(
                "qcow2: bad magic (not a qcow2 image)".into(),
            ));
        }
        let version = u32_be(buf, 4);
        if version != VERSION_V2 && version != VERSION_V3 {
            return Err(crate::Error::Unsupported(format!(
                "qcow2: only versions 2 and 3 are supported (got {version})"
            )));
        }
        let cluster_bits = u32_be(buf, 20);
        if !(9..=21).contains(&cluster_bits) {
            return Err(crate::Error::InvalidImage(format!(
                "qcow2: cluster_bits {cluster_bits} out of range [9, 21]"
            )));
        }
        let mut h = Self {
            version,
            backing_file_offset: u64_be(buf, 8),
            backing_file_size: u32_be(buf, 16),
            cluster_bits,
            size: u64_be(buf, 24),
            crypt_method: u32_be(buf, 32),
            l1_size: u32_be(buf, 36),
            l1_table_offset: u64_be(buf, 40),
            refcount_table_offset: u64_be(buf, 48),
            refcount_table_clusters: u32_be(buf, 56),
            nb_snapshots: u32_be(buf, 60),
            snapshots_offset: u64_be(buf, 64),
            incompatible_features: 0,
            compatible_features: 0,
            autoclear_features: 0,
            refcount_order: 4, // v2 implicit
            header_length: V2_HEADER_LEN as u32,
            compression_type: 0,
            extensions: Vec::new(),
        };
        if version == VERSION_V3 {
            if buf.len() < V3_HEADER_LEN {
                return Err(crate::Error::InvalidImage(format!(
                    "qcow2: v3 header truncated ({} bytes, need ≥ {V3_HEADER_LEN})",
                    buf.len()
                )));
            }
            h.incompatible_features = u64_be(buf, 72);
            h.compatible_features = u64_be(buf, 80);
            h.autoclear_features = u64_be(buf, 88);
            h.refcount_order = u32_be(buf, 96);
            h.header_length = u32_be(buf, 100);
            if h.header_length < V3_HEADER_LEN as u32 {
                return Err(crate::Error::InvalidImage(format!(
                    "qcow2: v3 header_length {} < {V3_HEADER_LEN}",
                    h.header_length
                )));
            }
            // `compression_type` is the first additional-field byte at offset
            // 104, present when the header extends past the fixed v3 layout.
            if h.header_length > V3_HEADER_LEN as u32 && buf.len() > V3_HEADER_LEN {
                h.compression_type = buf[V3_HEADER_LEN];
            }
        }
        // Extensions follow the fixed header. They end at the backing
        // filename when there is one (it is placed right after the chain),
        // otherwise at the end of whatever the caller read.
        let ext_start = h.header_length as usize;
        let ext_end = if h.backing_file_offset > 0 {
            (h.backing_file_offset as usize).min(buf.len())
        } else {
            buf.len()
        };
        if ext_start < ext_end {
            h.extensions = parse_extensions(buf, ext_start, ext_end);
        }
        h.validate()?;
        Ok(h)
    }

    /// Validate fields against fstool's supported subset.
    fn validate(&self) -> Result<()> {
        if self.crypt_method > crypt::LUKS {
            return Err(crate::Error::Unsupported(format!(
                "qcow2: unknown crypt_method {}",
                self.crypt_method
            )));
        }
        if self.refcount_order != 4 {
            return Err(crate::Error::Unsupported(format!(
                "qcow2: only refcount_order=4 (16-bit) is supported (got {})",
                self.refcount_order
            )));
        }
        // Compression is supported (zlib + zstd). The `COMPRESSION_TYPE`
        // incompatible bit must be set iff `compression_type` is non-zero,
        // and we only understand types 0 (zlib) and 1 (zstd).
        if self.compression_type > 1 {
            return Err(crate::Error::Unsupported(format!(
                "qcow2: unsupported compression_type {}",
                self.compression_type
            )));
        }
        let ctype_bit = self.incompatible_features & incompat::COMPRESSION_TYPE != 0;
        if ctype_bit != (self.compression_type != 0) {
            return Err(crate::Error::InvalidImage(
                "qcow2: COMPRESSION_TYPE incompatible bit disagrees with compression_type".into(),
            ));
        }
        let bad = self.incompatible_features
            & (incompat::DIRTY
                | incompat::CORRUPT
                | incompat::EXTERNAL_DATA_FILE
                | incompat::EXTENDED_L2);
        if bad != 0 {
            return Err(crate::Error::Unsupported(format!(
                "qcow2: incompatible features {bad:#x} not supported (dirty/corrupt/external-data/extended-L2)"
            )));
        }
        // Any other incompat bits we don't recognise → also refuse (spec
        // says we must refuse anything we don't understand). COMPRESSION_TYPE
        // is recognised and handled above.
        let known = incompat::DIRTY
            | incompat::CORRUPT
            | incompat::EXTERNAL_DATA_FILE
            | incompat::EXTENDED_L2
            | incompat::COMPRESSION_TYPE;
        let unknown = self.incompatible_features & !known;
        if unknown != 0 {
            return Err(crate::Error::Unsupported(format!(
                "qcow2: unknown incompatible_features {unknown:#x}"
            )));
        }
        Ok(())
    }

    /// Encode as a v3 header (always 104 bytes — we never write v2).
    /// Header extension area beyond is zero-padded by the caller out to
    /// a full cluster.
    pub fn encode_v3(&self) -> [u8; V3_HEADER_LEN] {
        let mut b = [0u8; V3_HEADER_LEN];
        b[0..4].copy_from_slice(&MAGIC);
        b[4..8].copy_from_slice(&VERSION_V3.to_be_bytes());
        b[8..16].copy_from_slice(&self.backing_file_offset.to_be_bytes());
        b[16..20].copy_from_slice(&self.backing_file_size.to_be_bytes());
        b[20..24].copy_from_slice(&self.cluster_bits.to_be_bytes());
        b[24..32].copy_from_slice(&self.size.to_be_bytes());
        b[32..36].copy_from_slice(&self.crypt_method.to_be_bytes());
        b[36..40].copy_from_slice(&self.l1_size.to_be_bytes());
        b[40..48].copy_from_slice(&self.l1_table_offset.to_be_bytes());
        b[48..56].copy_from_slice(&self.refcount_table_offset.to_be_bytes());
        b[56..60].copy_from_slice(&self.refcount_table_clusters.to_be_bytes());
        b[60..64].copy_from_slice(&self.nb_snapshots.to_be_bytes());
        b[64..72].copy_from_slice(&self.snapshots_offset.to_be_bytes());
        b[72..80].copy_from_slice(&self.incompatible_features.to_be_bytes());
        b[80..88].copy_from_slice(&self.compatible_features.to_be_bytes());
        b[88..96].copy_from_slice(&self.autoclear_features.to_be_bytes());
        b[96..100].copy_from_slice(&self.refcount_order.to_be_bytes());
        b[100..104].copy_from_slice(&(V3_HEADER_LEN as u32).to_be_bytes());
        b
    }
}

/// Read the first cluster's worth of header bytes from `r`. Returns the
/// full sector-aligned chunk so the caller can also inspect any v3
/// header extensions that follow the fixed-length section.
pub fn read_header_bytes(r: &mut (impl Read + ?Sized)) -> std::io::Result<[u8; V3_HEADER_LEN]> {
    let mut buf = [0u8; V3_HEADER_LEN];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn u32_be(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(buf[off..off + 4].try_into().unwrap())
}

fn u64_be(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(buf[off..off + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_v3_header() -> Header {
        Header {
            version: VERSION_V3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: 16,
            size: 64 * 1024 * 1024,
            crypt_method: 0,
            l1_size: 1,
            l1_table_offset: 3 * 65536,
            refcount_table_offset: 65536,
            refcount_table_clusters: 1,
            nb_snapshots: 0,
            snapshots_offset: 0,
            incompatible_features: 0,
            compatible_features: 0,
            autoclear_features: 0,
            refcount_order: 4,
            header_length: V3_HEADER_LEN as u32,
            compression_type: 0,
            extensions: Vec::new(),
        }
    }

    #[test]
    fn encode_decode_roundtrip_v3() {
        let h = sample_v3_header();
        let bytes = h.encode_v3();
        let decoded = Header::decode(&bytes).unwrap();
        assert_eq!(decoded.cluster_bits, 16);
        assert_eq!(decoded.cluster_size(), 65536);
        assert_eq!(decoded.size, 64 * 1024 * 1024);
        assert_eq!(decoded.l1_size, 1);
        assert_eq!(decoded.refcount_order, 4);
        assert_eq!(decoded.header_length, V3_HEADER_LEN as u32);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = sample_v3_header().encode_v3();
        bytes[0] = b'X';
        assert!(matches!(
            Header::decode(&bytes),
            Err(crate::Error::InvalidImage(_))
        ));
    }

    #[test]
    fn accepts_zstd_compression_type() {
        // COMPRESSION_TYPE incompat bit + compression_type=1 (zstd) is now
        // a supported, well-formed header.
        let mut h = sample_v3_header();
        h.incompatible_features = incompat::COMPRESSION_TYPE;
        let mut bytes = [0u8; 512];
        bytes[..V3_HEADER_LEN].copy_from_slice(&h.encode_v3());
        bytes[100..104].copy_from_slice(&112u32.to_be_bytes()); // header_length
        bytes[104] = 1; // compression_type = zstd
        let decoded = Header::decode(&bytes).unwrap();
        assert_eq!(decoded.compression_type, 1);
        assert!(decoded.incompatible_features & incompat::COMPRESSION_TYPE != 0);
    }

    #[test]
    fn rejects_inconsistent_compression_bit() {
        // COMPRESSION_TYPE bit set but compression_type still 0 → inconsistent.
        let mut h = sample_v3_header();
        h.incompatible_features = incompat::COMPRESSION_TYPE;
        let mut bytes = [0u8; 512];
        bytes[..V3_HEADER_LEN].copy_from_slice(&h.encode_v3());
        bytes[100..104].copy_from_slice(&112u32.to_be_bytes());
        // byte 104 stays 0.
        assert!(matches!(
            Header::decode(&bytes),
            Err(crate::Error::InvalidImage(_))
        ));
    }

    #[test]
    fn rejects_unknown_incompat_bit() {
        let mut h = sample_v3_header();
        h.incompatible_features = 1u64 << 30; // some future bit we don't know
        let bytes = h.encode_v3();
        assert!(matches!(
            Header::decode(&bytes),
            Err(crate::Error::Unsupported(_))
        ));
    }

    #[test]
    fn v2_decodes_with_defaults() {
        // Craft a v2 header by hand.
        let mut b = [0u8; V2_HEADER_LEN];
        b[0..4].copy_from_slice(&MAGIC);
        b[4..8].copy_from_slice(&2u32.to_be_bytes());
        b[20..24].copy_from_slice(&16u32.to_be_bytes()); // cluster_bits
        b[24..32].copy_from_slice(&(1024u64 * 1024 * 1024).to_be_bytes());
        b[36..40].copy_from_slice(&2u32.to_be_bytes()); // l1_size
        b[40..48].copy_from_slice(&(3 * 65536u64).to_be_bytes());
        b[48..56].copy_from_slice(&65536u64.to_be_bytes());
        b[56..60].copy_from_slice(&1u32.to_be_bytes());
        let h = Header::decode(&b).unwrap();
        assert_eq!(h.version, 2);
        assert_eq!(h.refcount_order, 4); // v2 implicit default
        assert_eq!(h.incompatible_features, 0);
    }
}
