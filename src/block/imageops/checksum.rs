//! Image checksums with an explicit scope.

use std::io::Read;
use std::path::Path;

use super::{COPY_CHUNK, open_source, to_hex};
use crate::Result;
use crate::md5::Md5;

/// A checksum algorithm fstool can compute.
///
/// [`ChecksumAlgorithm::from_name`] parses user input; names of algorithms
/// fstool knows of but cannot compute (SHA-1, SHA-256, …) are
/// [`crate::Error::Unsupported`], not silently mapped to something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChecksumAlgorithm {
    /// CRC-32 (IEEE 802.3, as zlib and UDIF use). The value is the 4
    /// big-endian bytes of the CRC.
    Crc32,
    /// MD5. The value is the 16-byte digest.
    Md5,
}

impl ChecksumAlgorithm {
    /// Parse a name: `crc32` (or `crc-32`, `crc`) or `md5`, any case.
    /// SHA-family and other recognised-but-uncomputable names are
    /// `Unsupported`; anything else is `InvalidArgument`.
    pub fn from_name(name: &str) -> Result<Self> {
        let n = name.trim().to_ascii_lowercase();
        Ok(match n.as_str() {
            "crc32" | "crc-32" | "crc" => Self::Crc32,
            "md5" => Self::Md5,
            "sha" | "sha1" | "sha-1" | "sha224" | "sha-224" | "sha256" | "sha-256" | "sha384"
            | "sha-384" | "sha512" | "sha-512" | "crc32c" | "ipod" => {
                return Err(crate::Error::Unsupported(format!(
                    "checksum algorithm {name:?} is not supported (fstool computes crc32 and md5)"
                )));
            }
            "udif-crc32" | "udif-md5" => {
                return Err(crate::Error::Unsupported(format!(
                    "{name:?} is a UDIF image's master checksum, not a hash of its bytes; \
                     use verify_udif / `fstool verify` to check it"
                )));
            }
            _ => {
                return Err(crate::Error::InvalidArgument(format!(
                    "unknown checksum algorithm {name:?} (expected crc32 or md5)"
                )));
            }
        })
    }

    /// The canonical name (`"crc32"`, `"md5"`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Crc32 => "crc32",
            Self::Md5 => "md5",
        }
    }

    /// The UDIF checksum type code (2, 4).
    pub fn udif_type(self) -> u32 {
        match self {
            Self::Crc32 => 2,
            Self::Md5 => 4,
        }
    }

    /// The algorithm a UDIF checksum type code names, if fstool can
    /// compute it.
    pub fn from_udif_type(kind: u32) -> Option<Self> {
        match kind {
            2 => Some(Self::Crc32),
            4 => Some(Self::Md5),
            _ => None,
        }
    }

    /// The value size in bits (32, 128).
    pub fn bits(self) -> u32 {
        match self {
            Self::Crc32 => 32,
            Self::Md5 => 128,
        }
    }
}

/// Incremental state for a [`ChecksumAlgorithm`].
#[derive(Clone)]
pub struct ChecksumHasher(Inner);

#[derive(Clone)]
enum Inner {
    Crc32(u32),
    Md5(Box<Md5>),
}

impl std::fmt::Debug for ChecksumHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ChecksumHasher")
            .field(&self.algorithm())
            .finish()
    }
}

impl ChecksumHasher {
    /// A fresh state.
    pub fn new(algorithm: ChecksumAlgorithm) -> Self {
        Self(match algorithm {
            ChecksumAlgorithm::Crc32 => Inner::Crc32(0),
            ChecksumAlgorithm::Md5 => Inner::Md5(Box::new(Md5::new())),
        })
    }

    /// The algorithm.
    pub fn algorithm(&self) -> ChecksumAlgorithm {
        match self.0 {
            Inner::Crc32(_) => ChecksumAlgorithm::Crc32,
            Inner::Md5(_) => ChecksumAlgorithm::Md5,
        }
    }

    /// Feed bytes.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.0 {
            Inner::Crc32(c) => *c = crate::crc::crc32_append(*c, data),
            Inner::Md5(m) => m.update(data),
        }
    }

    /// Feed `n` zero bytes.
    pub fn update_zeros(&mut self, mut n: u64) {
        let zero = [0u8; 4096];
        while n > 0 {
            let k = n.min(zero.len() as u64) as usize;
            self.update(&zero[..k]);
            n -= k as u64;
        }
    }

    /// The value: a CRC-32's 4 big-endian bytes, or the MD5 digest.
    pub fn finish(self) -> Vec<u8> {
        match self.0 {
            Inner::Crc32(c) => c.to_be_bytes().to_vec(),
            Inner::Md5(m) => m.finish().to_vec(),
        }
    }
}

/// What a checksum covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ChecksumScope {
    /// The decoded virtual disk: every logical sector, in order, as an
    /// attached image presents it. Independent of the container — a raw
    /// file, a UDIF of any format and a sparse image of the same disk
    /// agree. Equals `hdiutil checksum -type CRC32` / `-type MD5`.
    #[default]
    LogicalSectors,
    /// The bytes as stored: for a UDIF image its data fork (the chunk
    /// payloads, across every segment in order — what the trailer's
    /// data-fork checksum covers); for any other single-file image the
    /// whole file. A directory image (`.sparsebundle`) has no single byte
    /// stream and is refused.
    StoredBytes,
}

/// Options for [`image_checksum`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ChecksumOptions {
    /// What to cover. Default [`ChecksumScope::LogicalSectors`].
    pub scope: ChecksumScope,
    /// Passphrase for an encrypted source (LUKS, encrypted qcow2,
    /// `encrcdsa` `.dmg`), needed for the logical-sector scope. Encrypted
    /// sources are refused without one.
    pub password: Option<String>,
}

/// A computed checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageChecksum {
    /// The algorithm.
    pub algorithm: ChecksumAlgorithm,
    /// What it covers.
    pub scope: ChecksumScope,
    /// The value (see [`ChecksumHasher::finish`]).
    pub value: Vec<u8>,
    /// Bytes hashed.
    pub bytes: u64,
}

impl ImageChecksum {
    /// Lower-case hex of the value.
    pub fn hex(&self) -> String {
        to_hex(&self.value)
    }
}

/// Compute `algorithm` over the image at `path`, covering what
/// `opts.scope` says. Streams in 1 MiB pieces.
pub fn image_checksum(
    path: &Path,
    algorithm: ChecksumAlgorithm,
    opts: &ChecksumOptions,
) -> Result<ImageChecksum> {
    let mut h = ChecksumHasher::new(algorithm);
    let mut buf = vec![0u8; COPY_CHUNK];
    let mut bytes = 0u64;
    match opts.scope {
        ChecksumScope::LogicalSectors => {
            let mut dev = open_source(path, opts.password.as_deref())?;
            let total = dev.total_size();
            while bytes < total {
                let n = (total - bytes).min(buf.len() as u64) as usize;
                dev.read_at(bytes, &mut buf[..n])?;
                h.update(&buf[..n]);
                bytes += n as u64;
            }
        }
        ChecksumScope::StoredBytes => {
            if path.is_dir() {
                return Err(crate::Error::Unsupported(format!(
                    "{} is a directory image; it has no single stored byte stream to checksum",
                    path.display()
                )));
            }
            #[cfg(feature = "dmg")]
            if super::is_udif(path)? {
                let mut dev = crate::block::dmg::DmgBackend::open(path)?;
                let total = dev.info().fork_length;
                while bytes < total {
                    let n = (total - bytes).min(buf.len() as u64) as usize;
                    dev.read_fork(bytes, &mut buf[..n])?;
                    h.update(&buf[..n]);
                    bytes += n as u64;
                }
                return Ok(ImageChecksum {
                    algorithm,
                    scope: opts.scope,
                    value: h.finish(),
                    bytes,
                });
            }
            let mut f = std::fs::File::open(path)?;
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                h.update(&buf[..n]);
                bytes += n as u64;
            }
        }
    }
    Ok(ImageChecksum {
        algorithm,
        scope: opts.scope,
        value: h.finish(),
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_explicit() {
        assert_eq!(
            ChecksumAlgorithm::from_name("CRC32").unwrap(),
            ChecksumAlgorithm::Crc32
        );
        assert_eq!(
            ChecksumAlgorithm::from_name("md5").unwrap(),
            ChecksumAlgorithm::Md5
        );
        for n in ["sha256", "SHA-1", "udif-crc32"] {
            assert!(matches!(
                ChecksumAlgorithm::from_name(n),
                Err(crate::Error::Unsupported(_))
            ));
        }
        assert!(matches!(
            ChecksumAlgorithm::from_name("frob"),
            Err(crate::Error::InvalidArgument(_))
        ));
    }

    #[test]
    fn raw_file_scopes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.img");
        let data: Vec<u8> = (0..4096u32).map(|i| (i * 7) as u8).collect();
        std::fs::write(&p, &data).unwrap();
        for scope in [ChecksumScope::LogicalSectors, ChecksumScope::StoredBytes] {
            let o = ChecksumOptions {
                scope,
                ..Default::default()
            };
            let c = image_checksum(&p, ChecksumAlgorithm::Crc32, &o).unwrap();
            assert_eq!(c.value, crate::crc::crc32(&data).to_be_bytes());
            let m = image_checksum(&p, ChecksumAlgorithm::Md5, &o).unwrap();
            assert_eq!(m.value, crate::md5::md5(&data));
            assert_eq!(m.bytes, 4096);
        }
    }
}
