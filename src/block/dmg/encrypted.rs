//! Encrypted DMG (`encrcdsa` v2) read-only backend.
//!
//! ## Status
//!
//! - Detection: probe for the 8-byte magic `b"encrcdsa"` at offset 0.
//! - Header parse: full v2 layout — fixed prefix, key-entry table, and
//!   one PBKDF2 / wrapped-keyblob record per passphrase entry. Always
//!   available, regardless of the `dmg-encrypted` feature.
//! - Decryption (`dmg-encrypted` feature): PBKDF2-SHA1 → CBC unwrap of
//!   the keyblob (AES-192 on images `hdiutil` makes today, 3DES-EDE3 on
//!   older ones) → per-chunk AES-CBC decryption with chunk-indexed
//!   HMAC-SHA1 IVs.
//!
//! ## Format recap (v2)
//!
//! Apple's encrypted disk images carry an `encrcdsa` v2 header at offset
//! 0. The data fork that follows is split into fixed-size *chunks*
//! (`block_size` bytes each, 512 on images `hdiutil` makes); each chunk
//! is encrypted independently in AES-CBC with a per-chunk IV derived
//! from the chunk index plus an HMAC-SHA1 key. The *chunk encryption
//! key* (CEK) and IV-derivation key travel together in a keyblob that
//! is wrapped under a key derived from the user passphrase via
//! PBKDF2-SHA1.
//!
//! All multi-byte fields are big-endian on disk. Algorithm identifiers
//! are Apple CSSM `CSSM_ALGID_*` values (see [`algid`]).
//!
//! ```text
//!   0x00  8 bytes  magic  "encrcdsa"
//!   0x08  u32 BE   version  (= 2)
//!   0x0C  u32 BE   enc_iv_size (16 for AES-CBC)
//!   0x10  u32 BE   encryption_mode (CSSM block mode; 5 = CBC_IV8)
//!   0x14  u32 BE   encryption_algorithm (0x80000001 = AES)
//!   0x18  u32 BE   key_bits (128 or 256)
//!   0x1C  u32 BE   prng_algorithm
//!   0x20  u32 BE   prng_key_size
//!   0x24  16 bytes uuid
//!   0x34  u32 BE   block_size (chunk size in bytes)
//!   0x38  u64 BE   data_size (plaintext length in bytes)
//!   0x40  u64 BE   data_offset (absolute offset of the first chunk)
//!   0x48  u32 BE   key_count
//!   0x4C  key_count × { u32 BE type; u64 BE offset; u64 BE size }
//! ```
//!
//! Each key-entry row points (by absolute file offset) at a record whose
//! layout depends on `type`. Type 1 is a passphrase record:
//!
//! ```text
//!   0x00  u32 BE   kdf_algorithm (0x67 = PKCS5_PBKDF2)
//!   0x04  u32 BE   kdf_prng_algorithm
//!   0x08  u32 BE   pbkdf2_iteration_count
//!   0x0C  u32 BE   pbkdf2_salt_length
//!   0x10  32 bytes salt buffer (first salt_length bytes are live)
//!   0x30  u32 BE   blob_enc_iv_size
//!   0x34  32 bytes IV buffer (first iv_size bytes are live)
//!   0x54  u32 BE   blob_enc_key_bits (192)
//!   0x58  u32 BE   blob_enc_algorithm (0x80000001 = AES, 17 = 3DES_3KEY_EDE)
//!   0x5C  u32 BE   blob_enc_padding (7 = PKCS7)
//!   0x60  u32 BE   blob_enc_mode (6 = CBCPadIV8)
//!   0x64  u32 BE   encrypted_keyblob_size
//!   0x68  ...      encrypted_keyblob
//! ```
//!
//! After PBKDF2-SHA1 derives a `blob_enc_key_bits`-bit KEK from
//! `(password, salt, iter_count)`, the keyblob is CBC-decrypted under
//! `(KEK, IV)`. For AES the 8 live IV bytes are zero-extended to a
//! 16-byte block IV. PKCS#7 padding is removed; the plaintext is the
//! concatenation of the AES key (16 or 32 bytes) and the HMAC-SHA1 key
//! (20 bytes), possibly followed by trailing bytes we ignore. The chunk
//! IV is the first 16 bytes of `HMAC-SHA1(hmac_key, chunk_index_as_u32_be)`.
//!
//! The layout above was verified against images produced by
//! `hdiutil create -encryption AES-128` on current macOS; one such image
//! is checked in under `testdata/` and read by the unit tests.
//!
//! References (public reverse-engineering write-ups):
//!
//! - Jonathan Levin, *DMG file structure* (newosxbook.com).
//! - Public PKCS#5 / RFC 2898 (PBKDF2).
//! - Apple CDSA / CSSM algorithm-identifier documentation
//!   (PKCS5_PBKDF2 = 0x67, 3DES_3KEY_EDE = 0x11, AES = 0x80000001).
//!
//! No Apple source / SDK and no GPL-licensed reference implementation
//! was consulted while writing this module.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[cfg(feature = "dmg-encrypted")]
use std::io::{self, Write};

use crate::Result;
#[cfg(feature = "dmg-encrypted")]
use crate::block::BlockDevice;

/// Eight-byte v2 magic at file offset 0.
pub const ENCRCDSA_MAGIC: &[u8; 8] = b"encrcdsa";

/// Size of the fixed-layout prefix, up to and including `key_count`.
/// The key-entry table and the records it points at follow; their
/// extent is only known once the prefix has been decoded.
pub const ENCRCDSA_V2_HEADER_MIN_BYTES: usize = 0x4C;

/// Bytes per key-entry table row: `u32 type, u64 offset, u64 size`.
const KEY_ENTRY_BYTES: usize = 20;

/// Fixed part of a passphrase key record, up to and including
/// `encrypted_keyblob_size`.
const PASSPHRASE_RECORD_FIXED_BYTES: usize = 0x68;

/// Cap on `key_count`. Real images carry one entry (two with a
/// certificate); the cap keeps a hostile header from sizing the table
/// read off a 32-bit count.
const MAX_KEY_ENTRIES: u32 = 64;

/// Cap on a single key record's declared size (real ones are 0x268
/// bytes); bounds the per-entry read.
const MAX_KEY_RECORD_BYTES: u64 = 64 * 1024;

/// Apple CSSM algorithm identifiers as they appear in the header.
pub mod algid {
    /// `CSSM_ALGID_AES` — Apple's vendor-defined id for AES.
    pub const AES: u32 = 0x8000_0001;
    /// `CSSM_ALGID_3DES_3KEY_EDE`.
    pub const TDES_3KEY_EDE: u32 = 17;
    /// `CSSM_ALGID_PKCS5_PBKDF2`.
    pub const PKCS5_PBKDF2: u32 = 0x67;
}

/// Key-entry type for a passphrase-protected keyblob.
pub const KEY_ENTRY_PASSPHRASE: u32 = 1;

/// Cheap detector — peeks at the first 8 bytes of `path` and returns
/// `Ok(true)` when they match [`ENCRCDSA_MAGIC`]. Any I/O failure or
/// short read returns `Ok(false)` so callers can fall through to other
/// backends.
pub fn probe(path: &Path) -> Result<bool> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };
    let mut head = [0u8; 8];
    if f.read_exact(&mut head).is_err() {
        return Ok(false);
    }
    Ok(&head == ENCRCDSA_MAGIC)
}

/// One row of the key-entry table at offset 0x4C.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    /// Entry type; [`KEY_ENTRY_PASSPHRASE`] is the only one we unwrap.
    pub kind: u32,
    /// Absolute file offset of the record.
    pub offset: u64,
    /// Length of the record in bytes.
    pub size: u64,
}

/// A decoded passphrase (type 1) key record: the PBKDF2 parameters and
/// the wrapped keyblob they unlock.
///
/// Sized buffers are kept as raw 32-byte arrays plus a "live length" so
/// the reader can pass exactly the bytes that matter to PBKDF2 / CBC
/// while still letting a curious caller inspect the trailing zeros.
#[derive(Debug, Clone)]
pub struct PassphraseKey {
    /// KDF identifier; [`algid::PKCS5_PBKDF2`] in shipped images.
    pub kdf_algorithm: u32,
    /// PRNG used inside the KDF — Apple's keystore only ever picks
    /// HMAC-SHA1 in shipped images; we accept any value and let the
    /// decryption path assume SHA-1.
    pub kdf_prng_algorithm: u32,
    /// Number of PBKDF2 iterations. Hundreds of thousands on current
    /// images.
    pub pbkdf2_iteration_count: u32,
    /// Number of live bytes in `pbkdf2_salt`.
    pub pbkdf2_salt_length: u32,
    /// Salt buffer (32 bytes on disk; first `pbkdf2_salt_length` are live).
    pub pbkdf2_salt: [u8; 32],
    /// Number of live bytes in `blob_enc_iv`.
    pub blob_enc_iv_size: u32,
    /// IV buffer used to unwrap the keyblob (32 bytes on disk; first
    /// `blob_enc_iv_size` are live).
    pub blob_enc_iv: [u8; 32],
    /// Bit-length of the KEK; 192 on every image seen so far.
    pub blob_enc_key_bits: u32,
    /// Blob-wrap algorithm: [`algid::AES`] or [`algid::TDES_3KEY_EDE`].
    pub blob_enc_algorithm: u32,
    /// CSSM padding mode for the keyblob. PKCS#7 in shipped images.
    pub blob_enc_padding: u32,
    /// CSSM block-mode parameter; we don't act on it.
    pub blob_enc_mode: u32,
    /// Encrypted keyblob bytes, exactly `encrypted_keyblob_size` long.
    pub encrypted_keyblob: Vec<u8>,
}

impl PassphraseKey {
    /// Decode a passphrase record from `rec`, which starts at the
    /// record's first byte and spans at least its declared size.
    pub fn decode(rec: &[u8]) -> Result<Self> {
        if rec.len() < PASSPHRASE_RECORD_FIXED_BYTES {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: passphrase key record is {} bytes, need >= {PASSPHRASE_RECORD_FIXED_BYTES}",
                rec.len()
            )));
        }
        let kdf_algorithm = u32_be(rec, 0x00);
        let kdf_prng_algorithm = u32_be(rec, 0x04);
        let pbkdf2_iteration_count = u32_be(rec, 0x08);
        let pbkdf2_salt_length = u32_be(rec, 0x0C);
        // The salt buffer on disk is exactly 32 bytes; a larger live length
        // would make `salt()` slice past it and panic. Reject early.
        if pbkdf2_salt_length > 32 {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: pbkdf2_salt_length {pbkdf2_salt_length} exceeds 32-byte salt buffer"
            )));
        }
        let mut pbkdf2_salt = [0u8; 32];
        pbkdf2_salt.copy_from_slice(&rec[0x10..0x30]);
        let blob_enc_iv_size = u32_be(rec, 0x30);
        // Same for the IV buffer: 32 bytes on disk. We also require at least 8
        // live bytes — the smallest CBC IV either wrap cipher consumes.
        if blob_enc_iv_size > 32 {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: blob_enc_iv_size {blob_enc_iv_size} exceeds 32-byte IV buffer"
            )));
        }
        if blob_enc_iv_size < 8 {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: blob_enc_iv_size {blob_enc_iv_size} too small (need >= 8 for CBC)"
            )));
        }
        let mut blob_enc_iv = [0u8; 32];
        blob_enc_iv.copy_from_slice(&rec[0x34..0x54]);
        let blob_enc_key_bits = u32_be(rec, 0x54);
        let blob_enc_algorithm = u32_be(rec, 0x58);
        let blob_enc_padding = u32_be(rec, 0x5C);
        let blob_enc_mode = u32_be(rec, 0x60);
        let encrypted_keyblob_size = u32_be(rec, 0x64);

        let blob_end = PASSPHRASE_RECORD_FIXED_BYTES
            .checked_add(encrypted_keyblob_size as usize)
            .filter(|&end| end <= rec.len())
            .ok_or_else(|| {
                crate::Error::InvalidImage(format!(
                    "encrcdsa: keyblob ({encrypted_keyblob_size} bytes) overruns its \
                     {}-byte key record",
                    rec.len()
                ))
            })?;
        let encrypted_keyblob = rec[PASSPHRASE_RECORD_FIXED_BYTES..blob_end].to_vec();

        Ok(Self {
            kdf_algorithm,
            kdf_prng_algorithm,
            pbkdf2_iteration_count,
            pbkdf2_salt_length,
            pbkdf2_salt,
            blob_enc_iv_size,
            blob_enc_iv,
            blob_enc_key_bits,
            blob_enc_algorithm,
            blob_enc_padding,
            blob_enc_mode,
            encrypted_keyblob,
        })
    }

    /// Convenience accessor for the live salt slice.
    pub fn salt(&self) -> &[u8] {
        &self.pbkdf2_salt[..self.pbkdf2_salt_length as usize]
    }

    /// Convenience accessor for the live blob-IV slice.
    pub fn blob_iv(&self) -> &[u8] {
        &self.blob_enc_iv[..self.blob_enc_iv_size as usize]
    }
}

/// Decoded header for an `encrcdsa` v2 image: the fixed prefix, the
/// key-entry table, and every passphrase record the table points at.
#[derive(Debug, Clone)]
pub struct EncryptedDmgHeader {
    /// Format version — must be 2.
    pub version: u32,
    /// IV size for the chunk cipher, in bytes (16 for AES-CBC).
    pub enc_iv_size: u32,
    /// CSSM block mode for the chunk cipher (5 = CBC_IV8). Informational.
    pub encryption_mode: u32,
    /// Chunk cipher: [`algid::AES`] is the only one implemented.
    pub encryption_algorithm: u32,
    /// Chunk-cipher key length in bits: 128 or 256.
    pub key_bits: u32,
    /// PRNG that generated the keys. Informational.
    pub prng_algorithm: u32,
    /// PRNG key size. Informational.
    pub prng_key_size: u32,
    /// Image UUID.
    pub uuid: [u8; 16],
    /// Chunk size, in bytes. The data fork is split into non-overlapping
    /// chunks of this size, each independently AES-CBC encrypted; the
    /// last one may be shorter when `data_size` is not a multiple.
    pub block_size: u32,
    /// Length of the plaintext (and of the encrypted data fork) in bytes.
    pub data_size: u64,
    /// Absolute file offset of the first chunk's ciphertext.
    pub data_offset: u64,
    /// The key-entry table, in on-disk order.
    pub key_entries: Vec<KeyEntry>,
    /// Decoded passphrase records, in table order. Entries of other
    /// types (certificates) are listed in `key_entries` but not decoded.
    pub passphrase_keys: Vec<PassphraseKey>,
}

impl EncryptedDmgHeader {
    /// Decode the fixed prefix and the key-entry table from `buf`, which
    /// must start at file offset 0. Key records are *not* decoded — see
    /// [`decode`](Self::decode) — so this needs only the first
    /// `0x4C + 20 * key_count` bytes.
    pub fn decode_prefix(buf: &[u8]) -> Result<Self> {
        if buf.len() < ENCRCDSA_V2_HEADER_MIN_BYTES {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: header slice shorter than {ENCRCDSA_V2_HEADER_MIN_BYTES} bytes"
            )));
        }
        if &buf[0..8] != ENCRCDSA_MAGIC {
            return Err(crate::Error::InvalidImage(
                "encrcdsa: magic mismatch (expected \"encrcdsa\")".into(),
            ));
        }
        let version = u32_be(buf, 0x08);
        if version != 2 {
            return Err(crate::Error::Unsupported(format!(
                "encrcdsa: version {version} not supported (only v2)"
            )));
        }
        let enc_iv_size = u32_be(buf, 0x0C);
        let encryption_mode = u32_be(buf, 0x10);
        let encryption_algorithm = u32_be(buf, 0x14);
        let key_bits = u32_be(buf, 0x18);
        let prng_algorithm = u32_be(buf, 0x1C);
        let prng_key_size = u32_be(buf, 0x20);
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[0x24..0x34]);
        let block_size = u32_be(buf, 0x34);
        let data_size = u64_be(buf, 0x38);
        let data_offset = u64_be(buf, 0x40);
        let key_count = u32_be(buf, 0x48);
        if key_count > MAX_KEY_ENTRIES {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: key_count {key_count} exceeds maximum {MAX_KEY_ENTRIES}"
            )));
        }
        let table_end = ENCRCDSA_V2_HEADER_MIN_BYTES + key_count as usize * KEY_ENTRY_BYTES;
        if buf.len() < table_end {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: key-entry table ({key_count} entries) overruns the \
                 {}-byte header buffer",
                buf.len()
            )));
        }
        let key_entries = (0..key_count as usize)
            .map(|i| {
                let at = ENCRCDSA_V2_HEADER_MIN_BYTES + i * KEY_ENTRY_BYTES;
                KeyEntry {
                    kind: u32_be(buf, at),
                    offset: u64_be(buf, at + 4),
                    size: u64_be(buf, at + 12),
                }
            })
            .collect();

        Ok(Self {
            version,
            enc_iv_size,
            encryption_mode,
            encryption_algorithm,
            key_bits,
            prng_algorithm,
            prng_key_size,
            uuid,
            block_size,
            data_size,
            data_offset,
            key_entries,
            passphrase_keys: Vec::new(),
        })
    }

    /// How many bytes from file offset 0 a buffer must hold for
    /// [`decode`](Self::decode) to reach every key record: the end of
    /// the table, or of the farthest-reaching record, whichever is
    /// later. Records are bounds-checked here so a hostile table cannot
    /// request an unbounded read.
    pub fn required_len(&self) -> Result<usize> {
        let mut need = ENCRCDSA_V2_HEADER_MIN_BYTES + self.key_entries.len() * KEY_ENTRY_BYTES;
        for e in &self.key_entries {
            if e.size > MAX_KEY_RECORD_BYTES {
                return Err(crate::Error::InvalidImage(format!(
                    "encrcdsa: key record of {} bytes exceeds maximum {MAX_KEY_RECORD_BYTES}",
                    e.size
                )));
            }
            let end = e
                .offset
                .checked_add(e.size)
                .filter(|&end| end <= usize::MAX as u64)
                .ok_or_else(|| {
                    crate::Error::InvalidImage(
                        "encrcdsa: key record offset + size overflows".into(),
                    )
                })?;
            need = need.max(end as usize);
        }
        Ok(need)
    }

    /// Decode an `encrcdsa` v2 header from `buf`, including every
    /// passphrase key record the key-entry table points at.
    ///
    /// `buf` must start at file offset 0 and reach every record — see
    /// [`required_len`](Self::required_len).
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut h = Self::decode_prefix(buf)?;
        let need = h.required_len()?;
        if buf.len() < need {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: key records reach offset {need}, past the {}-byte header buffer",
                buf.len()
            )));
        }
        for e in &h.key_entries {
            if e.kind != KEY_ENTRY_PASSPHRASE {
                continue;
            }
            // `required_len` proved `offset + size` fits in the buffer.
            let rec = &buf[e.offset as usize..(e.offset + e.size) as usize];
            h.passphrase_keys.push(PassphraseKey::decode(rec)?);
        }
        Ok(h)
    }

    /// Number of chunks in the data fork (the last may be partial).
    pub fn n_chunks(&self) -> u64 {
        if self.block_size == 0 {
            return 0;
        }
        self.data_size.div_ceil(self.block_size as u64)
    }

    /// AES key length in bytes, derived from `key_bits`. Returns
    /// `Err(Unsupported)` for anything but 128, 192 and 256 bits.
    pub fn aes_key_len(&self) -> Result<usize> {
        match self.key_bits {
            128 => Ok(16),
            192 => Ok(24),
            256 => Ok(32),
            other => Err(crate::Error::Unsupported(format!(
                "encrcdsa: unsupported key_bits {other} (expected 128, 192 or 256)"
            ))),
        }
    }
}

fn u32_be(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(buf[at..at + 4].try_into().unwrap())
}

fn u64_be(buf: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(buf[at..at + 8].try_into().unwrap())
}

/// Read up to `len` bytes from the start of `file`; a short file yields
/// a short buffer, and the decoder reports what is missing.
fn read_prefix(file: &mut File, len: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut buf = Vec::with_capacity(len);
    file.take(len as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Read and decode the header off `file`, key records included. The
/// file cursor is left at an unspecified position; callers should seek
/// explicitly before the next read.
pub fn read_header(file: &mut File) -> Result<EncryptedDmgHeader> {
    // Two passes: the prefix and (capped) table tell us how far the key
    // records reach, then everything up to there is read and decoded.
    let table_max = ENCRCDSA_V2_HEADER_MIN_BYTES + MAX_KEY_ENTRIES as usize * KEY_ENTRY_BYTES;
    let head = read_prefix(file, table_max)?;
    let prefix = EncryptedDmgHeader::decode_prefix(&head)?;
    let need = prefix.required_len()?;
    let buf = if need <= head.len() {
        head
    } else {
        read_prefix(file, need)?
    };
    EncryptedDmgHeader::decode(&buf)
}

/// Read-only backend for password-protected DMGs (`encrcdsa` v2). Open
/// with [`EncryptedDmgBackend::open_with_password`].
///
/// The decrypted plaintext stream is `data_size` bytes long. Reads
/// slice into that virtual range; each chunk is decrypted on demand
/// using AES-CBC + a per-chunk IV derived from HMAC-SHA1.
///
/// The decrypted stream is what would normally be a *plain* DMG (or
/// raw filesystem image). Higher layers can hand this backend straight
/// to [`crate::block::dmg::DmgBackend`] if they want to read the
/// koly-trailer payload that lives inside, but we don't do that here —
/// scope of this module is the encryption layer alone.
#[cfg(feature = "dmg-encrypted")]
#[derive(Debug)]
pub struct EncryptedDmgBackend {
    file: File,
    header: EncryptedDmgHeader,
    /// AES key recovered from the keyblob — 16, 24 or 32 bytes.
    aes_key: Vec<u8>,
    /// HMAC-SHA1 key recovered from the keyblob — 20 bytes.
    hmac_key: [u8; 20],
    /// Cached plaintext size (`header.data_size`).
    virtual_size: u64,
    /// Implicit `Seek` cursor for the `Read` / `Seek` impls.
    cursor: u64,
}

#[cfg(feature = "dmg-encrypted")]
impl EncryptedDmgBackend {
    /// Open `path` as an encrypted DMG, authenticating with `password`.
    ///
    /// Every passphrase key entry is tried in turn. Fails with
    /// [`crate::Error::Unsupported`] when none unwraps to a keyblob with
    /// valid PKCS#7 padding — that's how CBC fails when the KEK is
    /// wrong, so the error variant doubles as a "wrong password" signal.
    pub fn open_with_password(path: &Path, password: &str) -> Result<Self> {
        let mut file = File::open(path)?;
        let header = read_header(&mut file)?;

        // Reject anything we don't actually implement.
        if header.encryption_algorithm != algid::AES {
            return Err(crate::Error::Unsupported(format!(
                "encrcdsa: encryption_algorithm {:#x} not supported (only {:#x} = AES)",
                header.encryption_algorithm,
                algid::AES
            )));
        }
        let aes_key_len = header.aes_key_len()?;
        if header.block_size == 0 || !header.block_size.is_multiple_of(16) {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: block_size {} is not a positive multiple of the 16-byte AES block",
                header.block_size
            )));
        }
        // `block_size` is attacker-controlled and sizes a per-chunk
        // `vec![0u8; block_size]` in `decrypt_chunk`. Real images use 512 B to
        // a few tens of KiB; cap at 1 MiB so a hostile header can't request a
        // ~4 GiB allocation per chunk read.
        const MAX_BLOCK_SIZE: u32 = 1 << 20;
        if header.block_size > MAX_BLOCK_SIZE {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: block_size {} exceeds maximum {MAX_BLOCK_SIZE}",
                header.block_size
            )));
        }
        // CBC without padding: a partial trailing chunk still has to be a
        // whole number of cipher blocks.
        if !header.data_size.is_multiple_of(16) {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: data_size {} is not a multiple of the 16-byte AES block",
                header.data_size
            )));
        }
        // The encrypted payload must physically fit between `data_offset`
        // and end-of-file. Rejecting a `data_size` the file can't back
        // stops a tiny image from advertising a huge virtual size.
        let file_len = file.metadata()?.len();
        let data_end = header
            .data_offset
            .checked_add(header.data_size)
            .ok_or_else(|| {
                crate::Error::InvalidImage("encrcdsa: data_offset + data_size overflows u64".into())
            })?;
        if data_end > file_len {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: data extent (offset {} + size {} = {}) exceeds file length {}",
                header.data_offset, header.data_size, data_end, file_len
            )));
        }
        if header.passphrase_keys.is_empty() {
            return Err(crate::Error::Unsupported(format!(
                "encrcdsa: no passphrase key entry among {} key entries \
                 (certificate-only images are not supported)",
                header.key_entries.len()
            )));
        }

        // Try each passphrase entry; the first that unwraps wins.
        let needed = aes_key_len + 20;
        let mut keyblob_plain = None;
        let mut last_err = None;
        for key in &header.passphrase_keys {
            match unwrap_keyblob(key, password) {
                Ok(plain) if plain.len() >= needed => {
                    keyblob_plain = Some(plain);
                    break;
                }
                Ok(plain) => {
                    last_err = Some(crate::Error::InvalidImage(format!(
                        "encrcdsa: unwrapped keyblob too short ({} bytes, need >= {needed})",
                        plain.len()
                    )));
                }
                Err(e) => last_err = Some(e),
            }
        }
        let keyblob_plain = match keyblob_plain {
            Some(p) => p,
            None => return Err(last_err.expect("at least one passphrase key was tried")),
        };

        // The plaintext is `aes_key || hmac_sha1_key`, sometimes followed by
        // a few trailing bytes we don't need.
        let aes_key = keyblob_plain[..aes_key_len].to_vec();
        let mut hmac_key = [0u8; 20];
        hmac_key.copy_from_slice(&keyblob_plain[aes_key_len..aes_key_len + 20]);

        let virtual_size = header.data_size;
        Ok(Self {
            file,
            header,
            aes_key,
            hmac_key,
            virtual_size,
            cursor: 0,
        })
    }

    /// Borrow the decoded header for diagnostics.
    pub fn header(&self) -> &EncryptedDmgHeader {
        &self.header
    }

    /// Byte length of chunk `chunk_index`: `block_size`, except for a
    /// partial trailing chunk.
    fn chunk_len(&self, chunk_base: u64) -> u64 {
        (self.header.block_size as u64).min(self.virtual_size - chunk_base)
    }

    /// Decrypt the `chunk_index`-th chunk into a fresh `Vec<u8>`. Used
    /// internally by [`read_at`].
    ///
    /// [`read_at`]: BlockDevice::read_at
    fn decrypt_chunk(&mut self, chunk_index: u64) -> Result<Vec<u8>> {
        // The IV derivation feeds the index to HMAC as a u32.
        let index32 = u32::try_from(chunk_index).map_err(|_| {
            crate::Error::InvalidImage(format!(
                "encrcdsa: chunk index {chunk_index} does not fit the 32-bit IV counter"
            ))
        })?;
        let rel = chunk_index * self.header.block_size as u64;
        let len = self.chunk_len(rel) as usize;
        let abs_offset = self.header.data_offset.checked_add(rel).ok_or_else(|| {
            crate::Error::InvalidImage(
                "encrcdsa: chunk absolute offset overflows the data fork".into(),
            )
        })?;
        self.file.seek(SeekFrom::Start(abs_offset))?;
        let mut ciphertext = vec![0u8; len];
        self.file.read_exact(&mut ciphertext)?;

        // IV = first 16 bytes of HMAC-SHA1(hmac_key, chunk_index_as_u32_be).
        let iv = chunk_iv(&self.hmac_key, index32);

        // AES-CBC decrypt in place. No padding — the chunk's ciphertext
        // is always a multiple of the AES block size (checked at open),
        // and the plaintext is the chunk's literal contents.
        aes_cbc_decrypt(&self.aes_key, &iv, &mut ciphertext)?;
        Ok(ciphertext)
    }
}

/// AES-CBC decrypt `buf` in place under a 16-, 24- or 32-byte key.
/// `buf.len()` MUST be a multiple of 16.
#[cfg(feature = "dmg-encrypted")]
fn aes_cbc_decrypt(key: &[u8], iv: &[u8; 16], buf: &mut [u8]) -> Result<()> {
    use purecrypto::cipher::{Aes128, Aes192, Aes256, Cbc};

    let res = match key.len() {
        16 => Cbc::new(Aes128::new(key.try_into().unwrap()), iv).decrypt(buf),
        24 => Cbc::new(Aes192::new(key.try_into().unwrap()), iv).decrypt(buf),
        32 => Cbc::new(Aes256::new(key.try_into().unwrap()), iv).decrypt(buf),
        other => {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: AES key has unexpected length {other}"
            )));
        }
    };
    res.map_err(|e| crate::Error::InvalidImage(format!("encrcdsa: AES-CBC: {e}")))
}

/// Derive the KEK from `password` and CBC-unwrap `key`'s keyblob with
/// it, stripping the PKCS#7 padding. Returns the plaintext keyblob.
#[cfg(feature = "dmg-encrypted")]
fn unwrap_keyblob(key: &PassphraseKey, password: &str) -> Result<Vec<u8>> {
    use purecrypto::cipher::{Cbc64, TdesEde3};

    if key.kdf_algorithm != algid::PKCS5_PBKDF2 {
        return Err(crate::Error::Unsupported(format!(
            "encrcdsa: kdf_algorithm {:#x} not supported (only {:#x} = PKCS5_PBKDF2)",
            key.kdf_algorithm,
            algid::PKCS5_PBKDF2
        )));
    }
    // Reject a zero iteration count up front — `purecrypto`'s pbkdf2 panics
    // on it, and it's a malformed header.
    if key.pbkdf2_iteration_count == 0 {
        return Err(crate::Error::InvalidImage(
            "encrcdsa: pbkdf2 iteration count is zero".into(),
        ));
    }
    let (block, kek_len) = match (key.blob_enc_algorithm, key.blob_enc_key_bits) {
        (algid::AES, 128) => (16usize, 16usize),
        (algid::AES, 192) => (16, 24),
        (algid::AES, 256) => (16, 32),
        (algid::TDES_3KEY_EDE, 192) => (8, 24),
        (alg, bits) => {
            return Err(crate::Error::Unsupported(format!(
                "encrcdsa: keyblob wrap algorithm {alg:#x} with {bits}-bit key not supported \
                 (only AES-128/192/256 and 3DES-EDE3)"
            )));
        }
    };
    let ct = &key.encrypted_keyblob;
    if ct.is_empty() || !ct.len().is_multiple_of(block) {
        return Err(crate::Error::InvalidImage(format!(
            "encrcdsa: keyblob ciphertext length {} is not a positive multiple of {block}",
            ct.len()
        )));
    }

    let mut kek = vec![0u8; kek_len];
    purecrypto::kdf::pbkdf2::<purecrypto::hash::Sha1>(
        password.as_bytes(),
        key.salt(),
        key.pbkdf2_iteration_count,
        &mut kek,
    );

    let mut buf = ct.clone();
    let iv = key.blob_iv();
    if block == 16 {
        // The header stores 8 live IV bytes even for AES (CSSM's
        // "CBCPadIV8" mode); they are zero-extended to a block.
        let mut iv16 = [0u8; 16];
        let n = iv.len().min(16);
        iv16[..n].copy_from_slice(&iv[..n]);
        aes_cbc_decrypt(&kek, &iv16, &mut buf)?;
    } else {
        let iv8: [u8; 8] = iv[..8].try_into().unwrap();
        let kek24: &[u8; 24] = kek.as_slice().try_into().unwrap();
        Cbc64::new(TdesEde3::new(kek24), &iv8)
            .decrypt(&mut buf)
            .map_err(|e| crate::Error::InvalidImage(format!("encrcdsa: 3DES-CBC: {e}")))?;
    }
    // `purecrypto`'s CBC is raw-block (caller pads), so strip PKCS#7 here.
    // A bad password yields garbage plaintext whose trailer fails this
    // check — that's the "wrong password" signal.
    let plain = strip_pkcs7(&buf, block).ok_or_else(|| {
        crate::Error::Unsupported(
            "encrcdsa: keyblob unwrap failed — wrong password, or unsupported padding".into(),
        )
    })?;
    Ok(plain.to_vec())
}

/// Strip PKCS#7 padding from `buf` (block size `block`, 1..=255). Returns
/// the unpadded prefix, or `None` if the padding is malformed.
#[cfg(feature = "dmg-encrypted")]
fn strip_pkcs7(buf: &[u8], block: usize) -> Option<&[u8]> {
    let n = *buf.last()? as usize;
    if n == 0 || n > block || n > buf.len() {
        return None;
    }
    let cut = buf.len() - n;
    if buf[cut..].iter().all(|&b| b as usize == n) {
        Some(&buf[..cut])
    } else {
        None
    }
}

/// Compute the AES-CBC IV for `chunk_index`: first 16 bytes of
/// `HMAC-SHA1(hmac_key, chunk_index_as_u32_be)`.
#[cfg(feature = "dmg-encrypted")]
fn chunk_iv(hmac_key: &[u8; 20], chunk_index: u32) -> [u8; 16] {
    use purecrypto::hash::{Hmac, Sha1};

    let tag = Hmac::<Sha1>::mac(hmac_key, &chunk_index.to_be_bytes());
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&tag[..16]);
    iv
}

#[cfg(feature = "dmg-encrypted")]
impl BlockDevice for EncryptedDmgBackend {
    fn block_size(&self) -> u32 {
        // Logical sector hint — surface 512 for parity with the rest
        // of the stack; the AES chunk size is a separate concept.
        512
    }

    fn total_size(&self) -> u64 {
        self.virtual_size
    }

    fn sync(&mut self) -> Result<()> {
        Ok(())
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let size = self.virtual_size;
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size,
            })?;
        if end > size {
            return Err(crate::Error::OutOfBounds {
                offset,
                len: buf.len() as u64,
                size,
            });
        }
        if buf.is_empty() {
            return Ok(());
        }

        let bs = self.header.block_size as u64;
        let mut filled = 0usize;
        let mut cursor = offset;
        while filled < buf.len() {
            let chunk_index = cursor / bs;
            let chunk_base = chunk_index * bs;
            let plain = self.decrypt_chunk(chunk_index)?;
            let local_start = (cursor - chunk_base) as usize;
            let available = plain.len() - local_start;
            let want = (buf.len() - filled).min(available);
            buf[filled..filled + want].copy_from_slice(&plain[local_start..local_start + want]);
            filled += want;
            cursor += want as u64;
        }
        Ok(())
    }

    fn write_at(&mut self, _offset: u64, _buf: &[u8]) -> Result<()> {
        Err(crate::Error::Unsupported(
            "encrcdsa: read-only container; writes are out of scope".into(),
        ))
    }
}

#[cfg(feature = "dmg-encrypted")]
impl Read for EncryptedDmgBackend {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cursor >= self.virtual_size {
            return Ok(0);
        }
        let remaining = self.virtual_size - self.cursor;
        let take = (buf.len() as u64).min(remaining) as usize;
        if take == 0 {
            return Ok(0);
        }
        self.read_at(self.cursor, &mut buf[..take])
            .map_err(|e| io::Error::other(format!("{e}")))?;
        self.cursor += take as u64;
        Ok(take)
    }
}

#[cfg(feature = "dmg-encrypted")]
impl Write for EncryptedDmgBackend {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("encrcdsa: read-only container"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "dmg-encrypted")]
impl Seek for EncryptedDmgBackend {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let total = self.virtual_size;
        let new = match pos {
            SeekFrom::Start(o) => o,
            SeekFrom::Current(d) => (self.cursor as i64).saturating_add(d).max(0) as u64,
            SeekFrom::End(d) => (total as i64).saturating_add(d).max(0) as u64,
        };
        self.cursor = new;
        Ok(new)
    }
}

/// Fallback when the crate is built without `dmg-encrypted`. The header
/// still parses (so `fstool inspect` can recognise an encrypted DMG and
/// say something useful), but the `open_with_password` constructor
/// returns `Unsupported`. We expose a zero-sized type so the public
/// surface is identical between feature flags.
#[cfg(not(feature = "dmg-encrypted"))]
#[derive(Debug)]
pub struct EncryptedDmgBackend {
    _never: std::convert::Infallible,
}

#[cfg(not(feature = "dmg-encrypted"))]
impl EncryptedDmgBackend {
    /// Stub for `--no-default-features` builds. Always returns
    /// [`crate::Error::Unsupported`] with a message pointing at the
    /// `dmg-encrypted` feature flag.
    pub fn open_with_password(_path: &Path, _password: &str) -> Result<Self> {
        Err(crate::Error::Unsupported(
            "encrcdsa: encrypted DMG support requires the `dmg-encrypted` Cargo feature".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Offset of the first (and only) key record in the synthetic
    /// headers below: right after a one-row key-entry table.
    const REC_OFFSET: usize = ENCRCDSA_V2_HEADER_MIN_BYTES + KEY_ENTRY_BYTES;

    /// Which cipher a synthetic fixture wraps its keyblob with.
    #[derive(Clone, Copy)]
    enum Wrap {
        Aes192,
        Tdes,
    }

    /// Encrypt-side helper mirroring the read path, used to synthesise
    /// fixtures. PKCS#7-pad `aes_key || hmac_key` to the wrap cipher's
    /// block and CBC-encrypt it under `(kek, iv8)` — the inverse of
    /// [`unwrap_keyblob`].
    #[cfg(feature = "dmg-encrypted")]
    fn encrypt_keyblob(
        wrap: Wrap,
        kek: &[u8; 24],
        iv8: &[u8; 8],
        aes_key: &[u8],
        hmac_key: &[u8; 20],
    ) -> Vec<u8> {
        use purecrypto::cipher::{Aes192, Cbc, Cbc64, TdesEde3};

        let mut blob = [aes_key, &hmac_key[..]].concat();
        match wrap {
            Wrap::Aes192 => {
                let pad = 16 - (blob.len() % 16);
                blob.extend(std::iter::repeat_n(pad as u8, pad));
                let mut iv16 = [0u8; 16];
                iv16[..8].copy_from_slice(iv8);
                Cbc::new(Aes192::new(kek), &iv16)
                    .encrypt(&mut blob)
                    .unwrap();
            }
            Wrap::Tdes => {
                let pad = 8 - (blob.len() % 8);
                blob.extend(std::iter::repeat_n(pad as u8, pad));
                Cbc64::new(TdesEde3::new(kek), iv8)
                    .encrypt(&mut blob)
                    .unwrap();
            }
        }
        blob
    }

    /// AES-CBC encrypt `buf` in place under a 16- or 32-byte key.
    #[cfg(feature = "dmg-encrypted")]
    fn aes_cbc_encrypt(key: &[u8], iv: &[u8; 16], buf: &mut [u8]) {
        use purecrypto::cipher::{Aes128, Aes256, Cbc};
        match key.len() {
            16 => Cbc::new(Aes128::new(key.try_into().unwrap()), iv)
                .encrypt(buf)
                .unwrap(),
            32 => Cbc::new(Aes256::new(key.try_into().unwrap()), iv)
                .encrypt(buf)
                .unwrap(),
            n => panic!("test AES key must be 16 or 32 bytes, got {n}"),
        }
    }

    /// Build a synthetic v2 header in the real on-disk layout: fixed
    /// prefix, a one-row key-entry table, and a passphrase record with
    /// the supplied KDF parameters and keyblob. Returns a fresh `Vec<u8>`
    /// of exactly `data_offset` bytes when that is past the record, so
    /// the caller can append chunk ciphertext directly.
    #[allow(clippy::too_many_arguments)]
    fn build_header_bytes(
        wrap: Wrap,
        iter_count: u32,
        salt: &[u8],
        blob_iv: &[u8],
        keyblob: &[u8],
        key_bits: u32,
        block_size: u32,
        data_size: u64,
        data_offset: u64,
    ) -> Vec<u8> {
        let rec_len = PASSPHRASE_RECORD_FIXED_BYTES + keyblob.len();
        let mut buf = vec![0u8; (REC_OFFSET + rec_len).max(data_offset as usize)];
        buf[0..8].copy_from_slice(ENCRCDSA_MAGIC);
        buf[0x08..0x0C].copy_from_slice(&2u32.to_be_bytes());
        buf[0x0C..0x10].copy_from_slice(&16u32.to_be_bytes());
        buf[0x10..0x14].copy_from_slice(&5u32.to_be_bytes()); // CBC_IV8
        buf[0x14..0x18].copy_from_slice(&algid::AES.to_be_bytes());
        buf[0x18..0x1C].copy_from_slice(&key_bits.to_be_bytes());
        buf[0x1C..0x20].copy_from_slice(&0x5Bu32.to_be_bytes());
        buf[0x20..0x24].copy_from_slice(&160u32.to_be_bytes());
        buf[0x24..0x34].copy_from_slice(b"fstool-test-uuid");
        buf[0x34..0x38].copy_from_slice(&block_size.to_be_bytes());
        buf[0x38..0x40].copy_from_slice(&data_size.to_be_bytes());
        buf[0x40..0x48].copy_from_slice(&data_offset.to_be_bytes());
        buf[0x48..0x4C].copy_from_slice(&1u32.to_be_bytes());
        // Key-entry table: one passphrase entry.
        buf[0x4C..0x50].copy_from_slice(&KEY_ENTRY_PASSPHRASE.to_be_bytes());
        buf[0x50..0x58].copy_from_slice(&(REC_OFFSET as u64).to_be_bytes());
        buf[0x58..0x60].copy_from_slice(&(rec_len as u64).to_be_bytes());
        // The record.
        let r = REC_OFFSET;
        buf[r..r + 4].copy_from_slice(&algid::PKCS5_PBKDF2.to_be_bytes());
        buf[r + 0x04..r + 0x08].copy_from_slice(&0u32.to_be_bytes());
        buf[r + 0x08..r + 0x0C].copy_from_slice(&iter_count.to_be_bytes());
        buf[r + 0x0C..r + 0x10].copy_from_slice(&(salt.len() as u32).to_be_bytes());
        buf[r + 0x10..r + 0x10 + salt.len()].copy_from_slice(salt);
        buf[r + 0x30..r + 0x34].copy_from_slice(&(blob_iv.len() as u32).to_be_bytes());
        buf[r + 0x34..r + 0x34 + blob_iv.len()].copy_from_slice(blob_iv);
        buf[r + 0x54..r + 0x58].copy_from_slice(&192u32.to_be_bytes());
        let alg = match wrap {
            Wrap::Aes192 => algid::AES,
            Wrap::Tdes => algid::TDES_3KEY_EDE,
        };
        buf[r + 0x58..r + 0x5C].copy_from_slice(&alg.to_be_bytes());
        buf[r + 0x5C..r + 0x60].copy_from_slice(&7u32.to_be_bytes()); // PKCS#7
        buf[r + 0x60..r + 0x64].copy_from_slice(&6u32.to_be_bytes()); // CBCPadIV8
        buf[r + 0x64..r + 0x68].copy_from_slice(&(keyblob.len() as u32).to_be_bytes());
        buf[r + 0x68..r + 0x68 + keyblob.len()].copy_from_slice(keyblob);
        buf
    }

    /// A header whose fields are plausible but whose keyblob is junk —
    /// enough for the decode-only tests.
    fn plain_header() -> Vec<u8> {
        build_header_bytes(
            Wrap::Aes192,
            1000,
            b"saltsaltsaltsaltsalt",
            b"iv8iv8iv",
            &[0u8; 48],
            128,
            512,
            4096,
            0x400,
        )
    }

    /// Interop guard for the key-derivation primitive: the bytes
    /// `purecrypto`'s PBKDF2-HMAC-SHA1 produces must match the RFC 6070
    /// known-answer vectors. This is what determines whether a genuine
    /// Apple `encrcdsa` image's KEK comes out right, so pin it to spec
    /// (transitively covering SHA-1 + HMAC-SHA1).
    #[cfg(feature = "dmg-encrypted")]
    #[test]
    fn pbkdf2_hmac_sha1_rfc6070() {
        fn derive(pw: &[u8], salt: &[u8], iters: u32, n: usize) -> Vec<u8> {
            let mut out = vec![0u8; n];
            purecrypto::kdf::pbkdf2::<purecrypto::hash::Sha1>(pw, salt, iters, &mut out);
            out
        }
        // RFC 6070 §2.
        assert_eq!(
            derive(b"password", b"salt", 1, 20),
            hex(b"0c60c80f961f0e71f3a9b524af6012062fe037a6")
        );
        assert_eq!(
            derive(b"password", b"salt", 2, 20),
            hex(b"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")
        );
        assert_eq!(
            derive(
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                25
            ),
            hex(b"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")
        );
    }

    /// Decode an ASCII-hex byte string into raw bytes (test helper).
    #[cfg(feature = "dmg-encrypted")]
    fn hex(s: &[u8]) -> Vec<u8> {
        s.chunks(2)
            .map(|c| {
                let v = std::str::from_utf8(c).unwrap();
                u8::from_str_radix(v, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn header_decodes_minimal_v2() {
        let buf = plain_header();
        let h = EncryptedDmgHeader::decode(&buf).unwrap();
        assert_eq!(h.version, 2);
        assert_eq!(h.encryption_algorithm, algid::AES);
        assert_eq!(h.key_bits, 128);
        assert_eq!(h.aes_key_len().unwrap(), 16);
        assert_eq!(h.block_size, 512);
        assert_eq!(h.data_size, 4096);
        assert_eq!(h.n_chunks(), 8);
        assert_eq!(h.data_offset, 0x400);
        assert_eq!(h.key_entries.len(), 1);
        assert_eq!(h.key_entries[0].kind, KEY_ENTRY_PASSPHRASE);
        assert_eq!(h.passphrase_keys.len(), 1);
        let k = &h.passphrase_keys[0];
        assert_eq!(k.kdf_algorithm, algid::PKCS5_PBKDF2);
        assert_eq!(k.pbkdf2_iteration_count, 1000);
        assert_eq!(k.salt(), b"saltsaltsaltsaltsalt");
        assert_eq!(k.blob_iv(), b"iv8iv8iv");
        assert_eq!(k.blob_enc_key_bits, 192);
        assert_eq!(k.blob_enc_algorithm, algid::AES);
        assert_eq!(k.encrypted_keyblob.len(), 48);
    }

    /// The header of a genuine `hdiutil` image decodes field-for-field
    /// as documented at the top of the module.
    #[test]
    fn header_decodes_real_hdiutil_image() {
        let img: &[u8] = include_bytes!("testdata/encrcdsa_aes128_fat12_hunter2.dmg");
        let h = EncryptedDmgHeader::decode(img).unwrap();
        assert_eq!(h.version, 2);
        assert_eq!(h.enc_iv_size, 16);
        assert_eq!(h.encryption_algorithm, algid::AES);
        assert_eq!(h.key_bits, 128);
        assert_eq!(h.block_size, 512);
        assert_eq!(h.data_size, 64 * 1024);
        assert_eq!(h.data_offset, 0x1DE00);
        assert_eq!(h.key_entries.len(), 1);
        assert_eq!(h.key_entries[0].kind, KEY_ENTRY_PASSPHRASE);
        assert_eq!(h.key_entries[0].offset, 0x60);
        assert_eq!(h.passphrase_keys.len(), 1);
        let k = &h.passphrase_keys[0];
        assert_eq!(k.kdf_algorithm, algid::PKCS5_PBKDF2);
        assert_eq!(k.pbkdf2_iteration_count, 625_000);
        assert_eq!(k.pbkdf2_salt_length, 20);
        assert_eq!(k.blob_enc_iv_size, 8);
        assert_eq!(k.blob_enc_key_bits, 192);
        assert_eq!(k.blob_enc_algorithm, algid::AES);
        assert_eq!(k.blob_enc_padding, 7);
        assert_eq!(k.encrypted_keyblob.len(), 0x30);
    }

    #[test]
    fn header_rejects_wrong_magic() {
        let mut buf = plain_header();
        buf[0] = b'X';
        let err = EncryptedDmgHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidImage(_)), "{err:?}");
    }

    #[test]
    fn header_rejects_v1() {
        let mut buf = plain_header();
        buf[0x08..0x0C].copy_from_slice(&1u32.to_be_bytes());
        let err = EncryptedDmgHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, crate::Error::Unsupported(_)), "{err:?}");
    }

    #[test]
    fn header_rejects_oversized_salt_length() {
        // salt() would slice past the 32-byte buffer and panic.
        let mut buf = plain_header();
        buf[REC_OFFSET + 0x0C..REC_OFFSET + 0x10].copy_from_slice(&33u32.to_be_bytes());
        let err = EncryptedDmgHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidImage(_)));
    }

    #[test]
    fn header_rejects_oversized_blob_iv_size() {
        // blob_iv() would slice past the 32-byte buffer and panic.
        let mut buf = plain_header();
        buf[REC_OFFSET + 0x30..REC_OFFSET + 0x34].copy_from_slice(&33u32.to_be_bytes());
        let err = EncryptedDmgHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidImage(_)));
    }

    #[test]
    fn header_rejects_undersized_blob_iv_size() {
        // < 8 live IV bytes can't drive the CBC unwrap.
        let mut buf = plain_header();
        buf[REC_OFFSET + 0x30..REC_OFFSET + 0x34].copy_from_slice(&4u32.to_be_bytes());
        let err = EncryptedDmgHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidImage(_)));
    }

    #[test]
    fn header_rejects_key_record_past_buffer() {
        // Point the key entry past the end of the buffer: the decoder must
        // refuse rather than slice out of bounds or read unboundedly.
        let mut buf = plain_header();
        let past_end = buf.len() as u64;
        buf[0x50..0x58].copy_from_slice(&past_end.to_be_bytes());
        let err = EncryptedDmgHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidImage(_)), "{err:?}");

        let mut buf = plain_header();
        buf[0x58..0x60].copy_from_slice(&u64::MAX.to_be_bytes());
        let err = EncryptedDmgHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidImage(_)), "{err:?}");
    }

    #[test]
    fn header_rejects_absurd_key_count() {
        let mut buf = plain_header();
        buf[0x48..0x4C].copy_from_slice(&u32::MAX.to_be_bytes());
        let err = EncryptedDmgHeader::decode(&buf).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidImage(_)), "{err:?}");
    }

    #[test]
    fn non_passphrase_entries_are_listed_but_not_decoded() {
        // Retype the only entry as a certificate entry: still listed in the
        // table, but no passphrase record comes out of it.
        let mut buf = plain_header();
        buf[0x4C..0x50].copy_from_slice(&2u32.to_be_bytes());
        let h = EncryptedDmgHeader::decode(&buf).unwrap();
        assert_eq!(h.key_entries.len(), 1);
        assert_eq!(h.key_entries[0].kind, 2);
        assert!(h.passphrase_keys.is_empty());
    }

    #[test]
    fn probe_recognises_v2_magic() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("enc.dmg");
        let mut content = vec![0u8; 128];
        content[..8].copy_from_slice(ENCRCDSA_MAGIC);
        std::fs::write(&p, &content).unwrap();
        assert!(probe(&p).unwrap());
    }

    #[test]
    fn probe_misses_unrelated_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("not-encrypted.dmg");
        std::fs::write(&p, b"random bytes").unwrap();
        assert!(!probe(&p).unwrap());
    }

    #[cfg(not(feature = "dmg-encrypted"))]
    #[test]
    fn open_returns_unsupported_without_feature() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("enc.dmg");
        std::fs::write(&p, ENCRCDSA_MAGIC).unwrap();
        let err = EncryptedDmgBackend::open_with_password(&p, "irrelevant").unwrap_err();
        match err {
            crate::Error::Unsupported(_) => {}
            _ => panic!("expected Unsupported, got {err:?}"),
        }
    }

    /// Synthesise a complete image: derive the KEK the way the open path
    /// does, wrap `aes_key || hmac_key`, encrypt `plain` chunk by chunk
    /// under the chunk-indexed IVs, and lay header + ciphertext out in a
    /// buffer. `plain.len()` need not be a multiple of `block_size`.
    #[cfg(feature = "dmg-encrypted")]
    #[allow(clippy::too_many_arguments)]
    fn synthesise_image(
        wrap: Wrap,
        password: &str,
        iter_count: u32,
        salt: &[u8],
        blob_iv8: &[u8; 8],
        aes_key: &[u8],
        hmac_key: &[u8; 20],
        block_size: u32,
        plain: &[u8],
    ) -> Vec<u8> {
        let mut kek = [0u8; 24];
        purecrypto::kdf::pbkdf2::<purecrypto::hash::Sha1>(
            password.as_bytes(),
            salt,
            iter_count,
            &mut kek,
        );
        let keyblob = encrypt_keyblob(wrap, &kek, blob_iv8, aes_key, hmac_key);
        let data_offset = 0x400u64;
        let mut file_bytes = build_header_bytes(
            wrap,
            iter_count,
            salt,
            blob_iv8,
            &keyblob,
            aes_key.len() as u32 * 8,
            block_size,
            plain.len() as u64,
            data_offset,
        );
        assert_eq!(file_bytes.len() as u64, data_offset);
        for (idx, chunk) in plain.chunks(block_size as usize).enumerate() {
            let mut ct = chunk.to_vec();
            aes_cbc_encrypt(aes_key, &chunk_iv(hmac_key, idx as u32), &mut ct);
            file_bytes.extend_from_slice(&ct);
        }
        file_bytes
    }

    /// Fill `n` bytes with a cheap non-repeating pattern.
    #[cfg(feature = "dmg-encrypted")]
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 31 + 7) ^ (i >> 4)) as u8).collect()
    }

    /// End-to-end synthesise + decrypt round trip for AES-128 with the
    /// AES-192 keyblob wrap current images use.
    #[cfg(feature = "dmg-encrypted")]
    #[test]
    fn round_trip_synthetic_aes128() {
        // Iteration count kept tiny on purpose — we don't want the test
        // suite to take seconds. Real images use 100k+.
        let plain = pattern(4096);
        let file_bytes = synthesise_image(
            Wrap::Aes192,
            "correct horse battery staple",
            100,
            b"saltsaltsaltsaltsalt",
            b"ivivivIV",
            b"AESKEY-128-BIT!!",
            b"HMACKEY-20-BYTES!!??",
            4096,
            &plain,
        );
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("enc.dmg");
        std::fs::write(&p, &file_bytes).unwrap();

        let mut be =
            EncryptedDmgBackend::open_with_password(&p, "correct horse battery staple").unwrap();
        assert_eq!(be.total_size(), 4096);
        let mut out = vec![0u8; 4096];
        be.read_at(0, &mut out).unwrap();
        assert_eq!(out, plain);

        // Mid-chunk slice.
        let mut mid = vec![0u8; 16];
        be.read_at(100, &mut mid).unwrap();
        assert_eq!(mid, &plain[100..116]);
    }

    /// Same with a 32-byte AES key (`key_bits = 256`), a 3DES keyblob
    /// wrap as older images carry, and a two-chunk payload so the
    /// second-chunk IV path runs. Also straddles the chunk boundary.
    #[cfg(feature = "dmg-encrypted")]
    #[test]
    fn round_trip_synthetic_aes256_tdes_wrap() {
        let plain: Vec<u8> = (0..8192usize)
            .map(|i| ((i ^ (i >> 4)) & 0xFF) as u8)
            .collect();
        let file_bytes = synthesise_image(
            Wrap::Tdes,
            "another-password",
            64,
            b"sodium_chloride_xx",
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            b"AES256-KEY-MATERIAL-32-BYTES---!",
            b"hmac-key-20-bytes-OK",
            4096,
            &plain,
        );
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("enc256.dmg");
        std::fs::write(&p, &file_bytes).unwrap();

        let mut be = EncryptedDmgBackend::open_with_password(&p, "another-password").unwrap();
        assert_eq!(be.total_size(), 8192);
        let mut out = vec![0u8; 8192];
        be.read_at(0, &mut out).unwrap();
        assert_eq!(out, plain);

        let mut cross = vec![0u8; 64];
        be.read_at(4096 - 32, &mut cross).unwrap();
        assert_eq!(&cross[..32], &plain[4096 - 32..4096]);
        assert_eq!(&cross[32..], &plain[4096..4096 + 32]);
    }

    /// A `data_size` that is not a multiple of `block_size` leaves a
    /// short trailing chunk, which must decrypt as far as it goes.
    #[cfg(feature = "dmg-encrypted")]
    #[test]
    fn partial_trailing_chunk() {
        let plain = pattern(512 * 3 + 64);
        let file_bytes = synthesise_image(
            Wrap::Aes192,
            "pw",
            50,
            b"saltsaltsaltsaltsalt",
            b"ivivivIV",
            b"AESKEY-128-BIT!!",
            b"HMACKEY-20-BYTES!!??",
            512,
            &plain,
        );
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("enc.dmg");
        std::fs::write(&p, &file_bytes).unwrap();

        let mut be = EncryptedDmgBackend::open_with_password(&p, "pw").unwrap();
        assert_eq!(be.total_size(), plain.len() as u64);
        let mut out = vec![0u8; plain.len()];
        be.read_at(0, &mut out).unwrap();
        assert_eq!(out, plain);
        let mut tail = [0u8; 16];
        be.read_at(plain.len() as u64 - 16, &mut tail).unwrap();
        assert_eq!(&tail, &plain[plain.len() - 16..]);
        let err = be.read_at(plain.len() as u64 - 8, &mut tail).unwrap_err();
        assert!(matches!(err, crate::Error::OutOfBounds { .. }));
    }

    /// Wrong password produces `Unsupported` from `unwrap_keyblob`
    /// (the PKCS#7 unpad fails). Confirms the error variant used as
    /// the "bad password" signal.
    #[cfg(feature = "dmg-encrypted")]
    #[test]
    fn wrong_password_rejected() {
        let file_bytes = synthesise_image(
            Wrap::Aes192,
            "supersecret",
            100,
            b"saltsaltsaltsaltsalt",
            b"ivivivIV",
            b"AESKEY-128-BIT!!",
            b"HMACKEY-20-BYTES!!??",
            4096,
            &[0u8; 4096],
        );
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("enc.dmg");
        std::fs::write(&p, &file_bytes).unwrap();

        let err = EncryptedDmgBackend::open_with_password(&p, "wrong-password").unwrap_err();
        match err {
            crate::Error::Unsupported(msg) => {
                assert!(msg.contains("wrong password") || msg.contains("padding"));
            }
            _ => panic!("expected Unsupported, got {err:?}"),
        }
    }

    /// Out-of-bounds read returns `OutOfBounds`.
    #[cfg(feature = "dmg-encrypted")]
    #[test]
    fn read_at_rejects_out_of_bounds() {
        let file_bytes = synthesise_image(
            Wrap::Aes192,
            "pw",
            50,
            b"saltsaltsaltsaltsalt",
            b"ivivivIV",
            b"AESKEY-128-BIT!!",
            b"HMACKEY-20-BYTES!!??",
            4096,
            &[0u8; 8192],
        );
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("enc.dmg");
        std::fs::write(&p, &file_bytes).unwrap();

        let mut be = EncryptedDmgBackend::open_with_password(&p, "pw").unwrap();
        assert_eq!(be.total_size(), 8192);
        let mut out = [0u8; 16];
        let err = be.read_at(8192, &mut out).unwrap_err();
        match err {
            crate::Error::OutOfBounds { .. } => {}
            _ => panic!("expected OutOfBounds, got {err:?}"),
        }
    }

    /// The real thing: a 64 KiB FAT12 volume made by
    /// `hdiutil create -encryption AES-128 -stdinpass -fs MS-DOS`, password
    /// `hunter2`. Decrypting it must expose the FAT boot sector — the
    /// 0x55AA signature at byte 510 and the `FAT12` type string.
    ///
    /// This is the only test that runs a production-strength PBKDF2
    /// (625 000 iterations), so it costs a few seconds in debug builds.
    #[cfg(feature = "dmg-encrypted")]
    #[test]
    fn decrypts_real_hdiutil_image() {
        let img: &[u8] = include_bytes!("testdata/encrcdsa_aes128_fat12_hunter2.dmg");
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("real.dmg");
        std::fs::write(&p, img).unwrap();

        let mut be = EncryptedDmgBackend::open_with_password(&p, "hunter2").unwrap();
        assert_eq!(be.total_size(), 64 * 1024);
        let mut boot = vec![0u8; 512];
        be.read_at(0, &mut boot).unwrap();
        assert_eq!(&boot[510..512], &[0x55, 0xAA], "boot signature");
        assert_eq!(&boot[0x36..0x3E], b"FAT12   ", "FAT type string");
        // Every chunk decrypts (no I/O or bounds error across the image),
        // and the first FAT starts with the media-descriptor entry.
        let mut all = vec![0u8; 64 * 1024];
        be.read_at(0, &mut all).unwrap();
        let reserved = u16::from_le_bytes([boot[14], boot[15]]) as usize;
        let bps = u16::from_le_bytes([boot[11], boot[12]]) as usize;
        assert_eq!(
            all[reserved * bps],
            boot[21],
            "FAT[0] carries the media byte"
        );
    }
}
