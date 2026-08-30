//! qcow2 encryption — both `crypt_method` values.
//!
//! qcow2 encrypts each 512-byte sector of *cluster* data independently.
//! Metadata (header, L1/L2 tables, refcounts) stays in the clear, so an
//! encrypted image still reports its virtual size, cluster size and
//! allocation map to anyone who looks — only the contents are protected.
//!
//! ## `crypt_method = 1` — the legacy AES scheme
//!
//! AES-128 in CBC, with the key taken *directly* from the passphrase:
//! the first 16 bytes, zero-padded. No salt, no KDF, no iteration count —
//! a dictionary attack costs one AES operation per guess. The IV is the
//! *guest* offset's sector index, little-endian, which also means two
//! images made from the same passphrase and the same contents produce
//! identical ciphertext.
//!
//! qemu has refused to *create* these since 2.9 and so do we; the format
//! is implemented here to read (and, in place, rewrite) images that
//! already exist. [`Qcow2Crypt::open_aes`] carries the same warning.
//!
//! ## `crypt_method = 2` — LUKS
//!
//! A complete LUKS1 header lives inside the image file, at the offset the
//! [`CRYPTO_HEADER`] extension names, with its clusters reserved in the
//! refcount table like any other metadata. Everything about it is
//! ordinary LUKS — passphrase → PBKDF2 → keyslot → anti-forensic merge →
//! master key — so [`crate::block::luks`] does that work unchanged. The
//! header's own `payload-offset` is vestigial: the payload is the qcow2
//! clusters, not a run of bytes after the header.
//!
//! The IV sector index here comes from the **host** offset — where the
//! cluster physically sits in the file — not the guest offset. That is
//! what lets a cluster be relocated without rewriting it… and equally,
//! what means a cluster's ciphertext changes if it ever moves.
//!
//! [`CRYPTO_HEADER`]: super::header::ext_type::CRYPTO_HEADER
//!
//! ## Alignment
//!
//! The unit of encryption is 512 bytes, so a read or write that starts or
//! ends mid-sector has to be widened to sector bounds (and, for a write,
//! read back first). [`Qcow2Crypt::sector_size`] is that unit; the
//! backend's I/O paths do the widening.
//!
//! ## Not supported
//!
//! Compressed clusters in an encrypted image. qemu refuses to produce
//! that combination, and an image claiming it is rejected rather than
//! decoded wrongly.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use crate::Result;
use crate::block::luks::crypt::{CipherSpec, SectorCipher};
use crate::block::luks::{self, v1};

use super::header::{Header, crypt, ext_type};

/// The unit qcow2 encrypts, in bytes. Fixed by the format.
pub const CRYPT_SECTOR_SIZE: u32 = 512;

/// Where an encrypted image's LUKS header lives inside the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoHeaderExtent {
    pub offset: u64,
    pub length: u64,
}

/// Locate the embedded crypto header from the header extensions.
pub fn crypto_header_extent(header: &Header) -> Result<Option<CryptoHeaderExtent>> {
    let Some(ext) = header
        .extensions
        .iter()
        .find(|e| e.kind == ext_type::CRYPTO_HEADER)
    else {
        return Ok(None);
    };
    if ext.data.len() < 16 {
        return Err(crate::Error::InvalidImage(format!(
            "qcow2: crypto-header extension is {} bytes, need 16",
            ext.data.len()
        )));
    }
    Ok(Some(CryptoHeaderExtent {
        offset: u64::from_be_bytes(ext.data[0..8].try_into().unwrap()),
        length: u64::from_be_bytes(ext.data[8..16].try_into().unwrap()),
    }))
}

/// Serialise a crypto-header extension payload.
pub fn crypto_header_ext_data(extent: CryptoHeaderExtent) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&extent.offset.to_be_bytes());
    v.extend_from_slice(&extent.length.to_be_bytes());
    v
}

/// The keyed cipher for an encrypted qcow2, plus which offset feeds the
/// IV generator.
pub struct Qcow2Crypt {
    cipher: SectorCipher,
    /// `true` for LUKS, where the sector index comes from the host (file)
    /// offset; `false` for the legacy AES scheme, which uses the guest
    /// offset.
    physical: bool,
    method: u32,
}

impl std::fmt::Debug for Qcow2Crypt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Qcow2Crypt")
            .field(
                "method",
                &match self.method {
                    crypt::AES => "aes",
                    crypt::LUKS => "luks",
                    _ => "?",
                },
            )
            .field("cipher", &self.cipher)
            .field("iv_from", &if self.physical { "host" } else { "guest" })
            .finish()
    }
}

impl Qcow2Crypt {
    /// Key the legacy AES scheme from `password`.
    ///
    /// The key *is* the password: its first 16 bytes, zero-padded to 16.
    /// There is no KDF to slow a guess down, so treat any image using
    /// this as readable by anyone willing to run a wordlist. It exists to
    /// open old images, not to protect new ones.
    pub fn open_aes(password: &str) -> Result<Self> {
        let mut key = [0u8; 16];
        let pw = password.as_bytes();
        let n = pw.len().min(16);
        key[..n].copy_from_slice(&pw[..n]);
        let spec = CipherSpec::parse("aes-cbc-plain64", 16)?;
        Ok(Self {
            cipher: SectorCipher::new(spec, &key, CRYPT_SECTOR_SIZE)?,
            physical: false,
            method: crypt::AES,
        })
    }

    /// Unlock the LUKS header embedded at `extent` in `file`.
    pub fn open_luks(file: &mut File, extent: CryptoHeaderExtent, password: &str) -> Result<Self> {
        let (spec, key) = unlock_embedded_luks(file, extent, password)?;
        Ok(Self {
            cipher: SectorCipher::new(spec, &key, CRYPT_SECTOR_SIZE)?,
            physical: true,
            method: crypt::LUKS,
        })
    }

    /// Key a LUKS engine directly from a master key — used right after
    /// [`create_luks_header`] writes one, so creation does not have to
    /// re-derive what it just generated.
    pub fn from_luks_master_key(spec: CipherSpec, key: &[u8]) -> Result<Self> {
        Ok(Self {
            cipher: SectorCipher::new(spec, key, CRYPT_SECTOR_SIZE)?,
            physical: true,
            method: crypt::LUKS,
        })
    }

    /// `crypt_method` this engine implements.
    pub fn method(&self) -> u32 {
        self.method
    }

    /// True when the IV comes from the host (file) offset rather than the
    /// guest offset — i.e. for LUKS.
    pub fn uses_host_offset(&self) -> bool {
        self.physical
    }

    /// The encryption unit, in bytes.
    pub fn sector_size(&self) -> u32 {
        CRYPT_SECTOR_SIZE
    }

    /// The keyed cipher, for diagnostics.
    pub fn cipher(&self) -> &SectorCipher {
        &self.cipher
    }

    /// Decrypt `buf` in place. `offset` is the byte offset the IV
    /// generator counts from — host or guest per
    /// [`uses_host_offset`](Self::uses_host_offset) — and must be a
    /// multiple of [`CRYPT_SECTOR_SIZE`], as must `buf.len()`.
    pub fn decrypt(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.cipher.decrypt(self.sector_of(offset)?, buf)
    }

    /// Encrypt `buf` in place. Mirrors [`decrypt`](Self::decrypt).
    pub fn encrypt(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.cipher.encrypt(self.sector_of(offset)?, buf)
    }

    fn sector_of(&self, offset: u64) -> Result<u64> {
        if !offset.is_multiple_of(CRYPT_SECTOR_SIZE as u64) {
            return Err(crate::Error::InvalidArgument(format!(
                "qcow2: crypto offset {offset} is not a multiple of {CRYPT_SECTOR_SIZE}"
            )));
        }
        Ok(offset / CRYPT_SECTOR_SIZE as u64)
    }
}

/// Read the embedded LUKS header and recover the volume cipher + master
/// key from `password`.
fn unlock_embedded_luks(
    file: &mut File,
    extent: CryptoHeaderExtent,
    password: &str,
) -> Result<(CipherSpec, Vec<u8>)> {
    let file_len = file.metadata()?.len();
    let end = extent.offset.checked_add(extent.length).ok_or_else(|| {
        crate::Error::InvalidImage("qcow2: crypto header extent overflows u64".into())
    })?;
    if extent.length < v1::PHDR_BYTES as u64 || end > file_len {
        return Err(crate::Error::InvalidImage(format!(
            "qcow2: crypto header at {} + {} does not lie inside the {file_len}-byte image",
            extent.offset, extent.length
        )));
    }

    let mut phdr = vec![0u8; v1::PHDR_BYTES];
    file.seek(SeekFrom::Start(extent.offset))?;
    file.read_exact(&mut phdr)?;

    match luks::detect(&phdr) {
        Some(luks::Version::V1) => {}
        Some(luks::Version::V2) => {
            return Err(crate::Error::Unsupported(
                "qcow2: the embedded crypto header is LUKS2; qemu writes LUKS1 \
                 here and fstool reads only that"
                    .into(),
            ));
        }
        None => {
            return Err(crate::Error::InvalidImage(
                "qcow2: the crypto-header extension does not point at a LUKS header".into(),
            ));
        }
    }

    let header = v1::Header::decode(&phdr)?;
    let spec = header.cipher_spec()?;

    for i in 0..v1::NUM_KEYS {
        if !header.slots[i].is_enabled() {
            continue;
        }
        // Keyslot offsets are relative to the embedded header's start,
        // not to the image file's.
        let (rel, len) = header.slot_material_extent(i);
        let at = extent
            .offset
            .checked_add(rel)
            .filter(|a| a + len <= end)
            .ok_or_else(|| {
                crate::Error::InvalidImage(format!(
                    "qcow2: embedded keyslot {i} material lies outside the crypto header"
                ))
            })?;
        let mut material = vec![0u8; len as usize];
        file.seek(SeekFrom::Start(at))?;
        file.read_exact(&mut material)?;
        if let Some(mk) = header.unlock_slot(i, password.as_bytes(), &mut material)? {
            return Ok((spec, mk));
        }
    }
    Err(crate::Error::InvalidArgument(
        "qcow2: no keyslot in the embedded LUKS header accepted the passphrase".into(),
    ))
}

/// A LUKS header built for embedding, plus what the caller needs to key
/// the engine and write the extension.
pub struct NewCryptoHeader {
    /// The header region, exactly `length` bytes.
    pub bytes: Vec<u8>,
    pub master_key: Vec<u8>,
    pub cipher_spec: CipherSpec,
}

/// Build the LUKS header an encrypted image embeds.
///
/// The region is the phdr plus all eight keyslot areas, with slot 0
/// carrying `password` — byte-identical in shape to what `qemu-img
/// create -o encrypt.format=luks` produces, so qemu opens the result.
pub fn create_luks_header(password: &str, opts: &luks::FormatOpts) -> Result<NewCryptoHeader> {
    if opts.version != luks::Version::V1 {
        return Err(crate::Error::InvalidArgument(
            "qcow2: an embedded crypto header must be LUKS1 — that is what \
             qemu writes and reads"
                .into(),
        ));
    }
    let spec = CipherSpec::parse(&opts.cipher, opts.key_bytes)?;
    let master_key = match &opts.master_key {
        Some(k) if k.len() == opts.key_bytes => k.clone(),
        Some(k) => {
            return Err(crate::Error::InvalidArgument(format!(
                "qcow2: supplied master key is {} bytes, key_bytes says {}",
                k.len(),
                opts.key_bytes
            )));
        }
        None => {
            let mut k = vec![0u8; opts.key_bytes];
            purecrypto::rng::RngCore::fill_bytes(&mut purecrypto::rng::OsRng, &mut k);
            k
        }
    };
    // The payload-offset field of an embedded header advertises the
    // region's own length: there is no payload laid out after it, and
    // that is the value qemu writes.
    let region_len = luks::v1::KEYSLOT_ALIGN + opts_slot_area(opts) * luks::v1::NUM_KEYS as u64;
    let image = luks::format::build_luks1(password, opts, region_len, &master_key)?;
    Ok(NewCryptoHeader {
        bytes: image.bytes,
        master_key: image.master_key,
        cipher_spec: spec,
    })
}

/// One keyslot area's size, rounded to the 4096-byte keyslot alignment.
/// Mirrors the private helper on `luks::FormatOpts`.
fn opts_slot_area(opts: &luks::FormatOpts) -> u64 {
    let exact = opts.stripes as u64 * opts.key_bytes as u64;
    exact.div_ceil(luks::v1::KEYSLOT_ALIGN) * luks::v1::KEYSLOT_ALIGN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_header_extension_round_trips() {
        let extent = CryptoHeaderExtent {
            offset: 262144,
            length: 2068480,
        };
        let data = crypto_header_ext_data(extent);
        assert_eq!(data.len(), 16);
        let mut h = super::super::header::Header::decode(&sample_header_bytes()).unwrap();
        h.extensions.push(super::super::header::Extension {
            kind: ext_type::CRYPTO_HEADER,
            data,
        });
        assert_eq!(crypto_header_extent(&h).unwrap(), Some(extent));
    }

    #[test]
    fn no_extension_means_no_extent() {
        let h = super::super::header::Header::decode(&sample_header_bytes()).unwrap();
        assert_eq!(crypto_header_extent(&h).unwrap(), None);
    }

    #[test]
    fn short_extension_is_rejected() {
        let mut h = super::super::header::Header::decode(&sample_header_bytes()).unwrap();
        h.extensions.push(super::super::header::Extension {
            kind: ext_type::CRYPTO_HEADER,
            data: vec![0u8; 8],
        });
        assert!(crypto_header_extent(&h).is_err());
    }

    /// The legacy scheme's key really is the passphrase, padded — pin
    /// that, because it is the whole reason the scheme is unsafe.
    #[test]
    fn legacy_aes_key_is_the_padded_password() {
        // Same passphrase truncated at 16 bytes must key identically.
        let a = Qcow2Crypt::open_aes("0123456789abcdef").unwrap();
        let b = Qcow2Crypt::open_aes("0123456789abcdefIGNORED").unwrap();
        let mut x = vec![0x11u8; 512];
        let mut y = vec![0x11u8; 512];
        a.encrypt(0, &mut x).unwrap();
        b.encrypt(0, &mut y).unwrap();
        assert_eq!(x, y);
        assert!(!a.uses_host_offset());
    }

    #[test]
    fn legacy_aes_round_trips_and_varies_by_sector() {
        let c = Qcow2Crypt::open_aes("swordfish").unwrap();
        let plain: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
        let mut buf = plain.clone();
        c.encrypt(4096, &mut buf).unwrap();
        assert_ne!(buf, plain);
        c.decrypt(4096, &mut buf).unwrap();
        assert_eq!(buf, plain);

        // Different offsets must produce different ciphertext.
        let mut a = vec![0u8; 512];
        let mut b = vec![0u8; 512];
        c.encrypt(0, &mut a).unwrap();
        c.encrypt(512, &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn unaligned_offsets_are_refused() {
        let c = Qcow2Crypt::open_aes("pw").unwrap();
        let mut buf = vec![0u8; 512];
        assert!(matches!(
            c.encrypt(100, &mut buf),
            Err(crate::Error::InvalidArgument(_))
        ));
    }

    #[test]
    fn embedded_header_must_be_luks1() {
        let opts = luks::FormatOpts {
            version: luks::Version::V2,
            ..luks::FormatOpts::fast_for_tests()
        };
        assert!(matches!(
            create_luks_header("pw", &opts),
            Err(crate::Error::InvalidArgument(_))
        ));
    }

    /// A header we build must be one our own reader unlocks, from bytes
    /// sitting at an arbitrary offset in a file.
    #[test]
    fn built_header_unlocks_from_a_file() {
        use std::io::Write as _;

        let opts = luks::FormatOpts {
            version: luks::Version::V1,
            ..luks::FormatOpts::fast_for_tests()
        };
        let built = create_luks_header("open me", &opts).unwrap();

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        // Put the header at a non-zero offset, as qcow2 does.
        tmp.write_all(&vec![0u8; 65536]).unwrap();
        tmp.write_all(&built.bytes).unwrap();
        tmp.flush().unwrap();

        let extent = CryptoHeaderExtent {
            offset: 65536,
            length: built.bytes.len() as u64,
        };
        let mut file = std::fs::File::open(tmp.path()).unwrap();
        let (spec, mk) = unlock_embedded_luks(&mut file, extent, "open me").unwrap();
        assert_eq!(mk, built.master_key);
        assert_eq!(spec, built.cipher_spec);

        // …and a wrong passphrase is refused.
        let err = unlock_embedded_luks(&mut file, extent, "nope").unwrap_err();
        assert!(matches!(err, crate::Error::InvalidArgument(_)), "{err}");
    }

    #[test]
    fn extent_outside_the_file_is_rejected() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut file = std::fs::File::open(tmp.path()).unwrap();
        let err = unlock_embedded_luks(
            &mut file,
            CryptoHeaderExtent {
                offset: 1 << 40,
                length: 4096,
            },
            "pw",
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidImage(_)), "{err}");
    }

    fn sample_header_bytes() -> [u8; 512] {
        let h = super::super::header::Header {
            version: super::super::header::VERSION_V3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: 16,
            size: 16 * 1024 * 1024,
            crypt_method: crypt::LUKS,
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
            header_length: super::super::header::V3_HEADER_LEN as u32,
            compression_type: 0,
            extensions: Vec::new(),
        };
        let mut b = [0u8; 512];
        b[..super::super::header::V3_HEADER_LEN].copy_from_slice(&h.encode_v3());
        b
    }
}
