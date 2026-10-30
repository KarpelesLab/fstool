//! Creating `encrcdsa` v2 images and managing their key records
//! (`dmg-encrypted-write` feature).
//!
//! - [`create_encrypted_image`] / [`create_encrypted_image_from_device`]
//!   wrap a payload — any image: raw, UDIF, a bare filesystem — in a
//!   passphrase-protected container that `hdiutil attach` opens.
//!   [`create_encrypted_image_with`] / [`create_encrypted_image_from_device_with`]
//!   take a list of [`Protector`]s instead: several passphrases and (with
//!   `dmg-encrypted-recovery`) recipient certificates, each becoming one
//!   key record.
//! - [`inspect_encrypted_image`] reports the header and every key record
//!   without deriving any key: passphrase records with their KDF cost,
//!   public-key (certificate) records with their recipient key id and wrap
//!   parameters, unknown record types as opaque.
//! - [`change_passphrase`] re-wraps the content key under a new
//!   passphrase in place — the same operation as `hdiutil chpass`. Only
//!   the one key record is rewritten; the payload is not touched.
//! - [`add_passphrase`] and `add_recipient` add a passphrase or
//!   recovery-certificate record, given a [`Credential`] that already
//!   opens the image.
//! - [`remove_key_record`] / [`remove_key_record_with`] drop a key record
//!   from the table and overwrite its bytes.
//!
//! Nothing here prompts or touches a keychain: passphrases, private keys,
//! certificates, content keys and the randomness source are all explicit
//! arguments. Output goes to a caller-owned `Write + Seek`; publishing it
//! (renaming a temporary file into place, say) is the caller's business,
//! and a failed call leaves the destination in an unspecified state that
//! must be discarded. The in-place editors verify the credential and build
//! every new byte before writing any, so a wrong passphrase or key, or a
//! damaged header, leaves the image untouched; an I/O error part-way
//! through the final write can still leave it inconsistent, so edit a copy
//! when that matters.
//!
//! ## What gets written
//!
//! The same layout `hdiutil create -encryption` produces on current
//! macOS: a key table at 0x4C with one row per record, the records packed
//! right after it in table order — 0x268-byte passphrase records, 0x234-byte
//! public-key records — and the payload starting at 0x1DE00 in 512-byte
//! chunks, each AES-CBC encrypted with the IV
//! `HMAC-SHA1(hmac_key, chunk_index)[..16]`. A passphrase record wraps the
//! keyblob (`aes_key || hmac_key || "CKIE" 0x00`) with AES-192-CBC under a
//! PBKDF2-HMAC-SHA1 key (20-byte salt, 8-byte IV); a public-key record
//! encrypts the same keyblob with RSAES-PKCS1-v1_5. With one passphrase
//! and one certificate, `hdiutil` puts the certificate record first; the
//! functions here keep the caller's order. The last chunk is zero-padded
//! to a whole chunk on disk; `data_size` records the exact payload length.
//!
//! Adding a record rewrites the key table and moves the existing records
//! (byte-for-byte) to keep them packed after the grown table.
//!
//! ## Limitations
//!
//! See the parent module's *Security properties*: the payload is **not
//! authenticated** (legacy CBC, no MAC), and removing or replacing a key
//! record is **not secure erasure** of earlier copies of it — nor does it
//! change the content key, so whoever saw the keyblob once keeps access.
//! Without `dmg-encrypted-recovery`, public-key records are reported and
//! preserved byte-for-byte but cannot be created or used.

use std::io::{Read, Seek, SeekFrom, Write};

use crate::Result;
use crate::block::BlockDevice;

#[cfg(feature = "dmg-encrypted-recovery")]
use super::RecipientKey;
use super::{
    Credential, ENCRCDSA_MAGIC, ENCRCDSA_V2_HEADER_MIN_BYTES, EncryptedDmgHeader, KEY_ENTRY_BYTES,
    KEY_ENTRY_PASSPHRASE, KEY_ENTRY_PUBLIC_KEY, KEYBLOB_TRAILER, MAX_CHUNK_SIZE, MAX_KEY_ENTRIES,
    MAX_PASSPHRASE_RECORDS, MAX_PBKDF2_ITERATIONS, PASSPHRASE_RECORD_FIXED_BYTES, PassphraseKey,
    PublicKeyRecord, SecretBytes, algid, chunk_iv, read_header_buf, record_bytes,
    validate_for_decryption, wipe,
};

/// PBKDF2 iteration count [`CreateOptions`] and [`RekeyOptions`] default
/// to — what `hdiutil` picked on the machine that made the checked-in
/// test image. `hdiutil` calibrates per machine; this is a fixed,
/// comparable cost.
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 625_000;

/// Chunk size [`CreateOptions`] defaults to — what `hdiutil` writes.
pub const DEFAULT_CHUNK_SIZE: u32 = 512;

/// Absolute offset of the first payload chunk in images this module
/// creates — the same as `hdiutil`'s, leaving the space after the key
/// record zeroed for further records.
pub const ENCRYPTED_DATA_OFFSET: u64 = 0x1DE00;

/// Most key records [`create_encrypted_image_with`] writes and
/// [`add_passphrase`] / `add_recipient` grow an image to. Of these at
/// most [`MAX_PASSPHRASE_RECORDS`](super::MAX_PASSPHRASE_RECORDS) may be
/// passphrase records — the most an unlock will try.
pub const MAX_PROTECTORS: usize = 16;

/// One way to open an image being created: each becomes one key record,
/// in the order given.
///
/// `Debug` never shows a passphrase.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum Protector<'a> {
    /// A passphrase record, PBKDF2-HMAC-SHA1 with
    /// [`CreateOptions::pbkdf2_iterations`].
    Passphrase(&'a str),
    /// A public-key (certificate) recovery record for this recipient —
    /// `hdiutil create -certificate`.
    #[cfg(feature = "dmg-encrypted-recovery")]
    Recipient(&'a RecipientKey),
}

impl std::fmt::Debug for Protector<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passphrase(_) => f.write_str("Passphrase(<redacted>)"),
            #[cfg(feature = "dmg-encrypted-recovery")]
            Self::Recipient(r) => f.debug_tuple("Recipient").field(r).finish(),
        }
    }
}

impl Protector<'_> {
    fn kind(&self) -> u32 {
        match self {
            Self::Passphrase(_) => KEY_ENTRY_PASSPHRASE,
            #[cfg(feature = "dmg-encrypted-recovery")]
            Self::Recipient(_) => KEY_ENTRY_PUBLIC_KEY,
        }
    }

    /// Build this protector's key record around `keyblob`.
    fn build(
        &self,
        keyblob: &[u8],
        iterations: u32,
        rng: &mut dyn RandomSource,
    ) -> Result<Vec<u8>> {
        match self {
            Self::Passphrase(p) => {
                build_passphrase_record(p, keyblob, iterations, PASSPHRASE_RECORD_BYTES, rng)
            }
            #[cfg(feature = "dmg-encrypted-recovery")]
            Self::Recipient(r) => r.build_record(keyblob, rng),
        }
    }
}

/// Check a set of key-record kinds against the limits: at least one
/// record, at most [`MAX_PROTECTORS`], at most
/// [`MAX_PASSPHRASE_RECORDS`] of them passphrase records.
fn check_record_kinds(kinds: impl Iterator<Item = u32>) -> Result<()> {
    let (mut total, mut pass) = (0usize, 0usize);
    for k in kinds {
        total += 1;
        pass += usize::from(k == KEY_ENTRY_PASSPHRASE);
    }
    if total == 0 {
        return Err(crate::Error::InvalidArgument(
            "encrcdsa: an image needs at least one passphrase or recipient".into(),
        ));
    }
    if total > MAX_PROTECTORS {
        return Err(crate::Error::InvalidArgument(format!(
            "encrcdsa: {total} key records exceed the maximum of {MAX_PROTECTORS}"
        )));
    }
    if pass > MAX_PASSPHRASE_RECORDS {
        return Err(crate::Error::InvalidArgument(format!(
            "encrcdsa: {pass} passphrase records exceed the maximum of {MAX_PASSPHRASE_RECORDS}"
        )));
    }
    Ok(())
}

/// Lay out a key area: the `key_count` field at 0x48, one table row per
/// `(kind, record)`, then the records packed right after the table in the
/// same order. Returns the bytes from 0x48 on.
fn build_key_area(records: &[(u32, Vec<u8>)], data_offset: u64) -> Result<Vec<u8>> {
    let base = ENCRCDSA_V2_HEADER_MIN_BYTES - 4;
    let table_end = ENCRCDSA_V2_HEADER_MIN_BYTES + records.len() * KEY_ENTRY_BYTES;
    let end = table_end + records.iter().map(|(_, r)| r.len()).sum::<usize>();
    if end as u64 > data_offset {
        return Err(crate::Error::InvalidArgument(format!(
            "encrcdsa: {} key records need {end} bytes of header, past the payload at \
             {data_offset:#x}",
            records.len()
        )));
    }
    let mut area = vec![0u8; end - base];
    area[..4].copy_from_slice(&(records.len() as u32).to_be_bytes());
    let mut at = table_end;
    for (i, (kind, rec)) in records.iter().enumerate() {
        let row = 4 + i * KEY_ENTRY_BYTES;
        area[row..row + 4].copy_from_slice(&kind.to_be_bytes());
        area[row + 4..row + 12].copy_from_slice(&(at as u64).to_be_bytes());
        area[row + 12..row + 20].copy_from_slice(&(rec.len() as u64).to_be_bytes());
        area[at - base..at - base + rec.len()].copy_from_slice(rec);
        at += rec.len();
    }
    Ok(area)
}

/// Size of a passphrase record as `hdiutil` lays it out: the fixed part
/// plus a 512-byte keyblob buffer.
const PASSPHRASE_RECORD_BYTES: usize = 0x268;

/// PBKDF2 salt length `hdiutil` uses.
const SALT_LEN: usize = 20;

/// Keyblob-wrap IV length (CSSM `CBCPadIV8`), zero-extended to an AES
/// block when used.
const BLOB_IV_LEN: usize = 8;

/// CSSM PRNG id and key size `hdiutil` stamps in the header.
/// Informational only; the reader ignores them.
const HEADER_PRNG_ALGORITHM: u32 = 0x5B;
const HEADER_PRNG_KEY_SIZE: u32 = 160;

/// CSSM block mode of the chunk cipher (`CBC_IV8`), as `hdiutil` writes.
const CHUNK_MODE_CBC_IV8: u32 = 5;

/// CSSM padding (`PKCS7`) and mode (`CBCPadIV8`) of the keyblob wrap.
const BLOB_PADDING_PKCS7: u32 = 7;
const BLOB_MODE_CBC_PAD_IV8: u32 = 6;

/// A source of random bytes for salts, IVs, the image UUID and generated
/// content keys.
///
/// [`OsRandom`] is the one to use; the trait exists so tests (and callers
/// with their own entropy source) can inject one. Any
/// `FnMut(&mut [u8])` closure implements it. **Must** be a CSPRNG outside
/// tests: the salt and IV are public, but a predictable content key is
/// the whole secret.
pub trait RandomSource {
    /// Fill `dest` entirely with random bytes.
    fn fill_random(&mut self, dest: &mut [u8]);
}

impl<F: FnMut(&mut [u8])> RandomSource for F {
    fn fill_random(&mut self, dest: &mut [u8]) {
        self(dest)
    }
}

/// The operating system's CSPRNG (via `purecrypto`'s `OsRng`:
/// `arc4random_buf` on Apple platforms, `/dev/urandom` / `getrandom`
/// elsewhere on Unix, `BCryptGenRandom` on Windows).
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill_random(&mut self, dest: &mut [u8]) {
        purecrypto::rng::RngCore::fill_bytes(&mut purecrypto::rng::OsRng, dest);
    }
}

/// Payload cipher of an `encrcdsa` image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ContentCipher {
    /// AES-128-CBC (`hdiutil -encryption AES-128`).
    Aes128,
    /// AES-256-CBC (`hdiutil -encryption AES-256`).
    Aes256,
}

impl ContentCipher {
    /// AES key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
        }
    }

    /// The header's `key_bits` value.
    pub fn key_bits(self) -> u32 {
        self.key_len() as u32 * 8
    }

    fn from_key_bits(bits: u32) -> Option<Self> {
        match bits {
            128 => Some(Self::Aes128),
            256 => Some(Self::Aes256),
            _ => None,
        }
    }
}

/// The content keys of an `encrcdsa` image: the AES key that encrypts the
/// payload chunks and the HMAC-SHA1 key that derives their IVs. These are
/// what a passphrase record wraps; changing the passphrase re-wraps them
/// without changing them.
///
/// Zeroed on drop; `Debug` shows only the cipher.
pub struct ContentKeys {
    cipher: ContentCipher,
    aes_key: SecretBytes,
    hmac_key: [u8; 20],
}

impl ContentKeys {
    /// Use caller-supplied key material. `aes_key` must be
    /// [`ContentCipher::key_len`] bytes and `hmac_key` 20 bytes.
    pub fn new(cipher: ContentCipher, aes_key: &[u8], hmac_key: &[u8]) -> Result<Self> {
        if aes_key.len() != cipher.key_len() {
            return Err(crate::Error::InvalidArgument(format!(
                "encrcdsa: {cipher:?} needs a {}-byte key, got {} bytes",
                cipher.key_len(),
                aes_key.len()
            )));
        }
        let hmac_key: [u8; 20] = hmac_key.try_into().map_err(|_| {
            crate::Error::InvalidArgument(format!(
                "encrcdsa: the IV-derivation HMAC key must be 20 bytes, got {}",
                hmac_key.len()
            ))
        })?;
        Ok(Self {
            cipher,
            aes_key: SecretBytes(aes_key.to_vec()),
            hmac_key,
        })
    }

    /// Draw fresh keys for `cipher` from `rng`.
    pub fn generate(cipher: ContentCipher, rng: &mut dyn RandomSource) -> Self {
        let mut aes_key = SecretBytes(vec![0u8; cipher.key_len()]);
        rng.fill_random(&mut aes_key.0);
        let mut hmac_key = [0u8; 20];
        rng.fill_random(&mut hmac_key);
        Self {
            cipher,
            aes_key,
            hmac_key,
        }
    }

    /// The payload cipher these keys are for.
    pub fn cipher(&self) -> ContentCipher {
        self.cipher
    }

    /// The AES content key.
    pub fn aes_key(&self) -> &[u8] {
        &self.aes_key.0
    }

    /// The HMAC-SHA1 key that derives chunk IVs.
    pub fn hmac_key(&self) -> &[u8; 20] {
        &self.hmac_key
    }

    /// The keyblob plaintext a passphrase record wraps:
    /// `aes_key || hmac_key || "CKIE" || 0x00`. The five-byte trailer is
    /// what `hdiutil` writes and — the PKCS#7 padding being too weak a
    /// check on its own — insists on finding when it unwraps a record.
    fn keyblob(&self) -> SecretBytes {
        SecretBytes(
            [
                &self.aes_key.0[..],
                &self.hmac_key[..],
                &KEYBLOB_TRAILER[..],
            ]
            .concat(),
        )
    }
}

impl Drop for ContentKeys {
    fn drop(&mut self) {
        wipe(&mut self.hmac_key);
    }
}

impl std::fmt::Debug for ContentKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentKeys")
            .field("cipher", &self.cipher)
            .field("aes_key", &"<redacted>")
            .field("hmac_key", &"<redacted>")
            .finish()
    }
}

/// Knobs for [`create_encrypted_image`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreateOptions {
    /// PBKDF2-HMAC-SHA1 iterations for the passphrase record. Must be
    /// between 1 and [`MAX_PBKDF2_ITERATIONS`]; the cost is the only thing
    /// slowing down a passphrase guesser, so keep the default unless you
    /// have a reason (tests do).
    pub pbkdf2_iterations: u32,
    /// Payload chunk size: a multiple of 16, at most
    /// [`MAX_CHUNK_SIZE`](super::MAX_CHUNK_SIZE). `hdiutil` uses 512.
    pub chunk_size: u32,
    /// Image UUID; a random (v4) one is drawn when `None`.
    pub uuid: Option<[u8; 16]>,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            pbkdf2_iterations: DEFAULT_PBKDF2_ITERATIONS,
            chunk_size: DEFAULT_CHUNK_SIZE,
            uuid: None,
        }
    }
}

/// Knobs for [`change_passphrase`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RekeyOptions {
    /// PBKDF2 iterations for the rewritten record (1 ..=
    /// [`MAX_PBKDF2_ITERATIONS`]).
    pub pbkdf2_iterations: u32,
}

impl Default for RekeyOptions {
    fn default() -> Self {
        Self {
            pbkdf2_iterations: DEFAULT_PBKDF2_ITERATIONS,
        }
    }
}

/// What [`create_encrypted_image`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CreatedImage {
    /// Total length of the container, in bytes, from offset 0 of the
    /// destination. Truncate a reused destination to this.
    pub image_len: u64,
    /// Plaintext payload length (`data_size`).
    pub payload_len: u64,
    /// The image UUID.
    pub uuid: [u8; 16],
}

/// Type of a key-table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyRecordKind {
    /// Type 1: a passphrase (PBKDF2) record.
    Passphrase,
    /// Type 2: a public-key / certificate recovery record (see
    /// [`PublicKeyRecord`](super::PublicKeyRecord)). Created and unlocked
    /// with the `dmg-encrypted-recovery` feature; always decoded by
    /// [`inspect_encrypted_image`] and preserved by the editors.
    PublicKey,
    /// Any other type, preserved byte-for-byte and reported as-is.
    Other(u32),
}

impl KeyRecordKind {
    fn from_raw(kind: u32) -> Self {
        match kind {
            KEY_ENTRY_PASSPHRASE => Self::Passphrase,
            KEY_ENTRY_PUBLIC_KEY => Self::PublicKey,
            other => Self::Other(other),
        }
    }
}

/// Non-secret parameters of a passphrase record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PassphraseRecordInfo {
    /// KDF id ([`algid::PKCS5_PBKDF2`] in every image seen).
    pub kdf_algorithm: u32,
    /// PBKDF2 iteration count the record asks for.
    pub pbkdf2_iterations: u32,
    /// Live salt length in bytes.
    pub salt_len: u32,
    /// Keyblob-wrap cipher id ([`algid::AES`] or
    /// [`algid::TDES_3KEY_EDE`]).
    pub wrap_algorithm: u32,
    /// Keyblob-wrap key length in bits (192 in every image seen).
    pub wrap_key_bits: u32,
    /// Length of the wrapped keyblob in bytes.
    pub wrapped_keyblob_len: usize,
    /// `false` when the iteration count exceeds [`MAX_PBKDF2_ITERATIONS`]
    /// (or is zero): this crate will refuse to run the KDF for it.
    pub within_limits: bool,
}

/// One entry of the key table, as [`inspect_encrypted_image`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyRecordInfo {
    /// Position in the key table (the `index` [`remove_key_record`] takes).
    pub index: usize,
    /// Entry type.
    pub kind: KeyRecordKind,
    /// Absolute offset of the record.
    pub offset: u64,
    /// Record length in bytes.
    pub size: u64,
    /// Decoded parameters, for passphrase records.
    pub passphrase: Option<PassphraseRecordInfo>,
    /// Decoded parameters, for public-key (certificate) records.
    pub public_key: Option<PublicKeyRecordInfo>,
}

/// Non-secret parameters of a public-key (certificate) recovery record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PublicKeyRecordInfo {
    /// The recipient key id the record names: SHA-1 of the recipient's
    /// PKCS#1 `RSAPublicKey` DER (compare with `RecipientKey::key_id` /
    /// `RecoveryKey::key_id`; it is also the hash `hdiutil -pubkey` takes).
    pub key_id: Vec<u8>,
    /// Wrap algorithm ([`algid::RSA`] in every image seen).
    pub wrap_algorithm: u32,
    /// Wrap padding
    /// ([`PUBLIC_KEY_PADDING_PKCS1`](super::PUBLIC_KEY_PADDING_PKCS1) in
    /// every image seen).
    pub wrap_padding: u32,
    /// Raw CSSM mode field (0 in every image seen).
    pub wrap_mode: u32,
    /// Length of the RSA ciphertext — the recipient's modulus length — in
    /// bytes.
    pub wrapped_keyblob_len: usize,
    /// `true` when this crate can unlock the record given the private key:
    /// RSA with PKCS#1 v1.5 padding, and a ciphertext length matching a
    /// 1024- to 4096-bit modulus. (Unlocking needs the
    /// `dmg-encrypted-recovery` feature.)
    pub supported: bool,
}

/// Everything [`inspect_encrypted_image`] can tell without a passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EncryptedImageInfo {
    /// Format version (2).
    pub version: u32,
    /// Payload cipher, when it is one this crate implements.
    pub cipher: Option<ContentCipher>,
    /// Raw `key_bits` field.
    pub key_bits: u32,
    /// Payload chunk size in bytes.
    pub chunk_size: u32,
    /// Plaintext payload length.
    pub payload_len: u64,
    /// Absolute offset of the first payload chunk.
    pub data_offset: u64,
    /// Image UUID.
    pub uuid: [u8; 16],
    /// The key table, in on-disk order.
    pub key_records: Vec<KeyRecordInfo>,
}

impl EncryptedImageInfo {
    /// Whether every passphrase record's KDF cost is within the limits
    /// this crate enforces.
    pub fn kdf_within_limits(&self) -> bool {
        self.key_records
            .iter()
            .filter_map(|r| r.passphrase.as_ref())
            .all(|p| p.within_limits)
    }
}

fn check_iterations(n: u32) -> Result<()> {
    if n == 0 || n > MAX_PBKDF2_ITERATIONS {
        return Err(crate::Error::InvalidArgument(format!(
            "encrcdsa: PBKDF2 iteration count {n} outside 1..={MAX_PBKDF2_ITERATIONS}"
        )));
    }
    Ok(())
}

/// AES-CBC encrypt `buf` (a multiple of 16 bytes) in place.
fn aes_cbc_encrypt(key: &[u8], iv: &[u8; 16], buf: &mut [u8]) -> Result<()> {
    use purecrypto::cipher::{Aes128, Aes192, Aes256, Cbc};

    let res = match key.len() {
        16 => Cbc::new(Aes128::new(key.try_into().unwrap()), iv).encrypt(buf),
        24 => Cbc::new(Aes192::new(key.try_into().unwrap()), iv).encrypt(buf),
        32 => Cbc::new(Aes256::new(key.try_into().unwrap()), iv).encrypt(buf),
        other => {
            return Err(crate::Error::InvalidArgument(format!(
                "encrcdsa: AES key has unexpected length {other}"
            )));
        }
    };
    res.map_err(|e| crate::Error::InvalidArgument(format!("encrcdsa: AES-CBC: {e}")))
}

/// Build a passphrase record `record_len` bytes long that wraps
/// `keyblob` under `passphrase`: fresh salt and IV from `rng`, PBKDF2-SHA1
/// → AES-192 KEK, AES-192-CBC with PKCS#7 padding — the parameters
/// `hdiutil` uses today.
fn build_passphrase_record(
    passphrase: &str,
    keyblob: &[u8],
    iterations: u32,
    record_len: usize,
    rng: &mut dyn RandomSource,
) -> Result<Vec<u8>> {
    check_iterations(iterations)?;
    let pad = 16 - keyblob.len() % 16;
    let wrapped_len = keyblob.len() + pad;
    if PASSPHRASE_RECORD_FIXED_BYTES + wrapped_len > record_len {
        return Err(crate::Error::InvalidImage(format!(
            "encrcdsa: a {wrapped_len}-byte wrapped keyblob does not fit a \
             {record_len}-byte key record"
        )));
    }

    let mut salt = [0u8; SALT_LEN];
    rng.fill_random(&mut salt);
    let mut iv8 = [0u8; BLOB_IV_LEN];
    rng.fill_random(&mut iv8);

    let mut kek = SecretBytes(vec![0u8; 24]);
    purecrypto::kdf::pbkdf2::<purecrypto::hash::Sha1>(
        passphrase.as_bytes(),
        &salt,
        iterations,
        &mut kek.0,
    );
    let mut blob = SecretBytes(Vec::with_capacity(wrapped_len));
    blob.0.extend_from_slice(keyblob);
    blob.0.extend(std::iter::repeat_n(pad as u8, pad));
    let mut iv16 = [0u8; 16];
    iv16[..BLOB_IV_LEN].copy_from_slice(&iv8);
    aes_cbc_encrypt(&kek.0, &iv16, &mut blob.0)?;

    let mut rec = vec![0u8; record_len];
    let put = |rec: &mut [u8], at: usize, v: u32| rec[at..at + 4].copy_from_slice(&v.to_be_bytes());
    put(&mut rec, 0x00, algid::PKCS5_PBKDF2);
    put(&mut rec, 0x04, 0); // kdf_prng_algorithm, as hdiutil writes
    put(&mut rec, 0x08, iterations);
    put(&mut rec, 0x0C, SALT_LEN as u32);
    rec[0x10..0x10 + SALT_LEN].copy_from_slice(&salt);
    put(&mut rec, 0x30, BLOB_IV_LEN as u32);
    rec[0x34..0x34 + BLOB_IV_LEN].copy_from_slice(&iv8);
    put(&mut rec, 0x54, 192);
    put(&mut rec, 0x58, algid::AES);
    put(&mut rec, 0x5C, BLOB_PADDING_PKCS7);
    put(&mut rec, 0x60, BLOB_MODE_CBC_PAD_IV8);
    put(&mut rec, 0x64, wrapped_len as u32);
    rec[PASSPHRASE_RECORD_FIXED_BYTES..PASSPHRASE_RECORD_FIXED_BYTES + wrapped_len]
        .copy_from_slice(&blob.0);
    Ok(rec)
}

/// Wrap `payload_len` bytes read from `payload` in a new passphrase-
/// protected `encrcdsa` v2 container written to `out`, starting at
/// offset 0 of `out`.
///
/// `keys` are the content keys — draw them with
/// [`ContentKeys::generate`] or supply your own; `rng` provides the
/// salt, the wrap IV and (unless [`CreateOptions::uuid`] is set) the
/// UUID. The payload can be anything — a raw disk image, a UDIF `.dmg`, a
/// bare filesystem; `hdiutil attach` opens it as it would the unencrypted
/// payload.
///
/// All parameters are checked and the key record is built before the
/// first byte is written. The header — and so the `encrcdsa` magic —
/// is written last, after the region it occupies has been zeroed, so a
/// run that fails part-way (a short payload, an I/O error) never leaves
/// a destination that looks like a finished image. Even so, the caller
/// owns `out` and should discard it on error.
///
/// Neither `passphrase` nor any key appears in an error message.
pub fn create_encrypted_image<W, R>(
    out: &mut W,
    payload: &mut R,
    payload_len: u64,
    passphrase: &str,
    keys: &ContentKeys,
    opts: &CreateOptions,
    rng: &mut dyn RandomSource,
) -> Result<CreatedImage>
where
    W: Write + Seek + ?Sized,
    R: Read + ?Sized,
{
    create_encrypted_image_with(
        out,
        payload,
        payload_len,
        &[Protector::Passphrase(passphrase)],
        keys,
        opts,
        rng,
    )
}

/// [`create_encrypted_image`] protected by any number of
/// [`Protector`]s — passphrases and recipient certificates — each
/// written as one key record, in order.
///
/// `hdiutil` itself makes images with one passphrase plus, optionally, one
/// certificate (`-certificate`), and lists the certificate record first;
/// it opens images with several passphrase records too, trying each. An
/// image protected only by certificates opens with
/// `hdiutil attach -recover <keychain>` or
/// [`EncryptedDmgBackend::open_with_recovery_key`](super::EncryptedDmgBackend).
///
/// Between 1 and [`MAX_PROTECTORS`] protectors, at most
/// [`MAX_PASSPHRASE_RECORDS`](super::MAX_PASSPHRASE_RECORDS) of them
/// passphrases. Everything else is as for [`create_encrypted_image`].
pub fn create_encrypted_image_with<W, R>(
    out: &mut W,
    payload: &mut R,
    payload_len: u64,
    protectors: &[Protector<'_>],
    keys: &ContentKeys,
    opts: &CreateOptions,
    rng: &mut dyn RandomSource,
) -> Result<CreatedImage>
where
    W: Write + Seek + ?Sized,
    R: Read + ?Sized,
{
    let plan = Plan::new(payload_len, protectors, keys, opts, rng)?;
    plan.write(out, keys, |buf| {
        payload.read_exact(buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => crate::Error::InvalidArgument(format!(
                "encrcdsa: payload ended before the declared {payload_len} bytes"
            )),
            _ => e.into(),
        })
    })
}

/// [`create_encrypted_image`] with the payload read from a
/// [`BlockDevice`] — its whole [`total_size`](BlockDevice::total_size).
pub fn create_encrypted_image_from_device<W>(
    out: &mut W,
    payload: &mut dyn BlockDevice,
    passphrase: &str,
    keys: &ContentKeys,
    opts: &CreateOptions,
    rng: &mut dyn RandomSource,
) -> Result<CreatedImage>
where
    W: Write + Seek + ?Sized,
{
    create_encrypted_image_from_device_with(
        out,
        payload,
        &[Protector::Passphrase(passphrase)],
        keys,
        opts,
        rng,
    )
}

/// [`create_encrypted_image_with`] with the payload read from a
/// [`BlockDevice`] — its whole [`total_size`](BlockDevice::total_size).
pub fn create_encrypted_image_from_device_with<W>(
    out: &mut W,
    payload: &mut dyn BlockDevice,
    protectors: &[Protector<'_>],
    keys: &ContentKeys,
    opts: &CreateOptions,
    rng: &mut dyn RandomSource,
) -> Result<CreatedImage>
where
    W: Write + Seek + ?Sized,
{
    let payload_len = payload.total_size();
    let plan = Plan::new(payload_len, protectors, keys, opts, rng)?;
    let mut pos = 0u64;
    plan.write(out, keys, |buf| {
        payload.read_at(pos, buf)?;
        pos += buf.len() as u64;
        Ok(())
    })
}

/// A validated creation: the header (key record included) is built, so
/// only the payload streaming remains.
struct Plan {
    header: Vec<u8>,
    chunk_size: u32,
    payload_len: u64,
    n_chunks: u64,
    uuid: [u8; 16],
}

impl Plan {
    fn new(
        payload_len: u64,
        protectors: &[Protector<'_>],
        keys: &ContentKeys,
        opts: &CreateOptions,
        rng: &mut dyn RandomSource,
    ) -> Result<Self> {
        check_record_kinds(protectors.iter().map(Protector::kind))?;
        check_iterations(opts.pbkdf2_iterations)?;
        let cs = opts.chunk_size;
        if cs == 0 || !cs.is_multiple_of(16) || cs > MAX_CHUNK_SIZE {
            return Err(crate::Error::InvalidArgument(format!(
                "encrcdsa: chunk size {cs} must be a positive multiple of 16, at most \
                 {MAX_CHUNK_SIZE}"
            )));
        }
        let n_chunks = payload_len.div_ceil(u64::from(cs));
        if n_chunks > u64::from(u32::MAX) + 1 {
            return Err(crate::Error::InvalidArgument(format!(
                "encrcdsa: a {payload_len}-byte payload needs more {cs}-byte chunks than the \
                 32-bit IV counter allows; use a larger chunk size"
            )));
        }
        n_chunks
            .checked_mul(u64::from(cs))
            .and_then(|n| n.checked_add(ENCRYPTED_DATA_OFFSET))
            .ok_or_else(|| {
                crate::Error::InvalidArgument("encrcdsa: payload length overflows".into())
            })?;

        let uuid = match opts.uuid {
            Some(u) => u,
            None => {
                let mut u = [0u8; 16];
                rng.fill_random(&mut u);
                u[6] = (u[6] & 0x0F) | 0x40; // version 4
                u[8] = (u[8] & 0x3F) | 0x80; // RFC 4122 variant
                u
            }
        };
        let keyblob = keys.keyblob();
        let records = protectors
            .iter()
            .map(|p| Ok((p.kind(), p.build(&keyblob.0, opts.pbkdf2_iterations, rng)?)))
            .collect::<Result<Vec<_>>>()?;
        let area = build_key_area(&records, ENCRYPTED_DATA_OFFSET)?;

        let mut h = vec![0u8; ENCRYPTED_DATA_OFFSET as usize];
        let put32 =
            |h: &mut [u8], at: usize, v: u32| h[at..at + 4].copy_from_slice(&v.to_be_bytes());
        let put64 =
            |h: &mut [u8], at: usize, v: u64| h[at..at + 8].copy_from_slice(&v.to_be_bytes());
        h[0..8].copy_from_slice(ENCRCDSA_MAGIC);
        put32(&mut h, 0x08, 2);
        put32(&mut h, 0x0C, 16);
        put32(&mut h, 0x10, CHUNK_MODE_CBC_IV8);
        put32(&mut h, 0x14, algid::AES);
        put32(&mut h, 0x18, keys.cipher.key_bits());
        put32(&mut h, 0x1C, HEADER_PRNG_ALGORITHM);
        put32(&mut h, 0x20, HEADER_PRNG_KEY_SIZE);
        h[0x24..0x34].copy_from_slice(&uuid);
        put32(&mut h, 0x34, cs);
        put64(&mut h, 0x38, payload_len);
        put64(&mut h, 0x40, ENCRYPTED_DATA_OFFSET);
        let base = ENCRCDSA_V2_HEADER_MIN_BYTES - 4;
        h[base..base + area.len()].copy_from_slice(&area);

        // Self-check: the header we built must decode back to what we meant.
        let back = EncryptedDmgHeader::decode(&h)?;
        debug_assert_eq!(back.key_entries.len(), protectors.len());
        debug_assert_eq!(back.data_size, payload_len);

        Ok(Self {
            header: h,
            chunk_size: cs,
            payload_len,
            n_chunks,
            uuid,
        })
    }

    fn write<W: Write + Seek + ?Sized>(
        &self,
        out: &mut W,
        keys: &ContentKeys,
        mut fill: impl FnMut(&mut [u8]) -> Result<()>,
    ) -> Result<CreatedImage> {
        // Clear the header region first so a stale header in a reused
        // destination can't outlive a failed run.
        out.seek(SeekFrom::Start(0))?;
        out.write_all(&vec![0u8; self.header.len()])?;

        let cs = self.chunk_size as usize;
        let mut buf = SecretBytes(vec![0u8; cs]);
        let mut remaining = self.payload_len;
        for idx in 0..self.n_chunks {
            let take = remaining.min(cs as u64) as usize;
            fill(&mut buf.0[..take])?;
            buf.0[take..].fill(0);
            remaining -= take as u64;
            // `n_chunks <= 2^32` was checked, so the index fits.
            let iv = chunk_iv(keys.hmac_key(), idx as u32);
            aes_cbc_encrypt(keys.aes_key(), &iv, &mut buf.0)?;
            out.write_all(&buf.0)?;
        }

        out.seek(SeekFrom::Start(0))?;
        out.write_all(&self.header)?;
        out.flush()?;
        Ok(CreatedImage {
            image_len: ENCRYPTED_DATA_OFFSET + self.n_chunks * self.chunk_size as u64,
            payload_len: self.payload_len,
            uuid: self.uuid,
        })
    }
}

/// Decode an image's header and key table without deriving any key.
///
/// Bounded like the reader: at most 64 key entries and 64 KiB per record
/// are read. Passphrase records are decoded and their KDF cost reported
/// ([`PassphraseRecordInfo::within_limits`]); public-key records are
/// decoded down to their recipient key id
/// ([`PublicKeyRecordInfo`]); other record types are listed as opaque.
/// Malformed headers and records are errors.
pub fn inspect_encrypted_image<R: Read + Seek + ?Sized>(
    image: &mut R,
) -> Result<EncryptedImageInfo> {
    let (h, buf) = read_header_buf(image)?;
    let mut pass = h.passphrase_keys.iter();
    let key_records = h
        .key_entries
        .iter()
        .enumerate()
        .map(|(index, e)| {
            let kind = KeyRecordKind::from_raw(e.kind);
            let passphrase = (kind == KeyRecordKind::Passphrase)
                .then(|| pass.next())
                .flatten()
                .map(passphrase_info);
            let public_key = if kind == KeyRecordKind::PublicKey {
                Some(public_key_info(&PublicKeyRecord::decode(record_bytes(
                    &h, &buf, index,
                ))?))
            } else {
                None
            };
            Ok(KeyRecordInfo {
                index,
                kind,
                offset: e.offset,
                size: e.size,
                passphrase,
                public_key,
            })
        })
        .collect::<Result<_>>()?;
    Ok(EncryptedImageInfo {
        version: h.version,
        cipher: (h.encryption_algorithm == algid::AES)
            .then(|| ContentCipher::from_key_bits(h.key_bits))
            .flatten(),
        key_bits: h.key_bits,
        chunk_size: h.block_size,
        payload_len: h.data_size,
        data_offset: h.data_offset,
        uuid: h.uuid,
        key_records,
    })
}

fn passphrase_info(k: &PassphraseKey) -> PassphraseRecordInfo {
    PassphraseRecordInfo {
        kdf_algorithm: k.kdf_algorithm,
        pbkdf2_iterations: k.pbkdf2_iteration_count,
        salt_len: k.pbkdf2_salt_length,
        wrap_algorithm: k.blob_enc_algorithm,
        wrap_key_bits: k.blob_enc_key_bits,
        wrapped_keyblob_len: k.encrypted_keyblob.len(),
        within_limits: (1..=MAX_PBKDF2_ITERATIONS).contains(&k.pbkdf2_iteration_count),
    }
}

fn public_key_info(r: &PublicKeyRecord) -> PublicKeyRecordInfo {
    let n = r.wrapped_keyblob.len();
    PublicKeyRecordInfo {
        key_id: r.key_id().to_vec(),
        wrap_algorithm: r.wrap_algorithm,
        wrap_padding: r.wrap_padding,
        wrap_mode: r.wrap_mode,
        wrapped_keyblob_len: n,
        supported: r.wrap_algorithm == algid::RSA
            && r.wrap_padding == super::PUBLIC_KEY_PADDING_PKCS1
            && (128..=512).contains(&n),
    }
}

/// Read and check a header for an in-place key-table edit: decodable,
/// decryptable, and with every key record lying between the key table and
/// the payload, so rewriting one can never touch the table or the data.
/// Also returns the header buffer (see [`read_header_buf`]).
fn header_for_edit<F: Read + Seek + ?Sized>(
    image: &mut F,
) -> Result<(EncryptedDmgHeader, Vec<u8>)> {
    let (h, buf) = read_header_buf(image)?;
    let file_len = image.seek(SeekFrom::End(0))?;
    validate_for_decryption(&h, file_len)?;
    let table_end = (ENCRCDSA_V2_HEADER_MIN_BYTES + h.key_entries.len() * KEY_ENTRY_BYTES) as u64;
    for (i, e) in h.key_entries.iter().enumerate() {
        // `read_header_buf` proved `offset + size` does not overflow.
        if e.offset < table_end || e.offset + e.size > h.data_offset {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: key record {i} ({} bytes at {:#x}) is not between the key table and \
                 the payload; refusing to edit it in place",
                e.size, e.offset
            )));
        }
    }
    Ok((h, buf))
}

/// Change the passphrase of an image in place — `hdiutil chpass`.
///
/// `old` must unlock one of the passphrase records (they are tried in
/// table order; the first that unlocks is the one changed). "Unlocks"
/// here means the unwrapped keyblob carries the
/// [`KEYBLOB_TRAILER`](super::KEYBLOB_TRAILER) every `hdiutil` image has,
/// not merely valid padding — a wrong passphrase passes the padding check
/// about once in 256 tries, and re-wrapping the garbage it yields would
/// lock the image for good. Images whose keyblob lacks the trailer are
/// therefore refused. That
/// record's bytes are replaced with a new one wrapping the **same**
/// content keys under `new`, with a fresh salt and IV from `rng` and
/// [`RekeyOptions::pbkdf2_iterations`]. Nothing else is written: other
/// key records — passphrase, certificate or unknown — and the payload
/// stay byte-for-byte as they were.
///
/// A wrong `old` passphrase or a damaged header fails before anything is
/// written. Returns the key-table index of the rewritten record.
///
/// The content keys do not change, so anyone who saved the old record (a
/// backup copy of the image) and knows the old passphrase can still
/// decrypt the payload. See the module docs.
pub fn change_passphrase<F: Read + Write + Seek + ?Sized>(
    image: &mut F,
    old: &str,
    new: &str,
    opts: &RekeyOptions,
    rng: &mut dyn RandomSource,
) -> Result<usize> {
    check_iterations(opts.pbkdf2_iterations)?;
    let (h, buf) = header_for_edit(image)?;
    let (index, keyblob) = super::unlock_with(&h, &buf, Credential::Passphrase(old), None, true)?;
    let entry = &h.key_entries[index];
    let record = build_passphrase_record(
        new,
        &keyblob.0,
        opts.pbkdf2_iterations,
        // `required_len` capped the size at 64 KiB.
        entry.size as usize,
        rng,
    )?;
    // Check the record round-trips before committing it.
    let decoded = PassphraseKey::decode(&record)?;
    debug_assert_eq!(decoded.pbkdf2_iteration_count, opts.pbkdf2_iterations);
    image.seek(SeekFrom::Start(entry.offset))?;
    image.write_all(&record)?;
    image.flush()?;
    Ok(index)
}

/// Add a key record built around the image's keyblob, after `credential`
/// unlocked it: the table grows by one row, existing records are moved
/// (byte-for-byte, in table order) to stay packed after it, and the new
/// record goes last. Returns the new record's key-table index.
fn add_record<F: Read + Write + Seek + ?Sized>(
    image: &mut F,
    credential: Credential<'_>,
    kind: u32,
    build: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
) -> Result<usize> {
    let (h, buf) = header_for_edit(image)?;
    let n = h.key_entries.len();
    check_record_kinds(
        h.key_entries
            .iter()
            .map(|e| e.kind)
            .chain(std::iter::once(kind)),
    )?;
    debug_assert!(n < MAX_KEY_ENTRIES as usize);
    let (_, keyblob) = super::unlock_with(&h, &buf, credential, None, true)?;
    let new = build(&keyblob.0)?;
    let mut records: Vec<(u32, Vec<u8>)> = h
        .key_entries
        .iter()
        .enumerate()
        .map(|(i, e)| (e.kind, record_bytes(&h, &buf, i).to_vec()))
        .collect();
    records.push((kind, new));
    let mut area = build_key_area(&records, h.data_offset)?;
    // Zero whatever the old layout used beyond the new one, so no stale
    // copy of a moved record lingers in this file.
    let base = ENCRCDSA_V2_HEADER_MIN_BYTES - 4;
    let old_end = buf.len().min(h.data_offset as usize);
    if old_end > base + area.len() {
        area.resize(old_end - base, 0);
    }
    // Self-check before committing: the new header decodes, with the
    // records where we put them.
    let mut check = buf[..base].to_vec();
    check.extend_from_slice(&area);
    let back = EncryptedDmgHeader::decode(&check)?;
    if back.key_entries.len() != n + 1 || back.key_entries[n].kind != kind {
        return Err(crate::Error::InvalidImage(
            "encrcdsa: rebuilt key table failed its self-check".into(),
        ));
    }
    image.seek(SeekFrom::Start(base as u64))?;
    image.write_all(&area)?;
    image.flush()?;
    Ok(n)
}

/// Add a passphrase record for `new` to an image in place, given a
/// `credential` that already opens it — something `hdiutil chpass`
/// cannot do, though `hdiutil attach` accepts each passphrase record of
/// an image that has several.
///
/// The new record wraps the **same** content keys (fresh salt and IV,
/// [`RekeyOptions::pbkdf2_iterations`]); the payload is untouched. Up to
/// [`MAX_PASSPHRASE_RECORDS`](super::MAX_PASSPHRASE_RECORDS) passphrase
/// records and [`MAX_PROTECTORS`] records in all. As for
/// [`change_passphrase`], the credential must unwrap to a keyblob carrying
/// the `CKIE` trailer, and a wrong credential or a damaged header fails
/// before anything is written. Returns the new record's key-table index
/// (the last).
pub fn add_passphrase<F: Read + Write + Seek + ?Sized>(
    image: &mut F,
    credential: Credential<'_>,
    new: &str,
    opts: &RekeyOptions,
    rng: &mut dyn RandomSource,
) -> Result<usize> {
    check_iterations(opts.pbkdf2_iterations)?;
    add_record(image, credential, KEY_ENTRY_PASSPHRASE, |keyblob| {
        build_passphrase_record(
            new,
            keyblob,
            opts.pbkdf2_iterations,
            PASSPHRASE_RECORD_BYTES,
            rng,
        )
    })
}

/// Add a public-key (certificate) recovery record for `recipient` to an
/// image in place, given a `credential` that already opens it — what
/// `hdiutil create -certificate` sets up at creation time. The holder of
/// the matching private key can then open the image without a passphrase
/// (`hdiutil attach -recover`,
/// [`EncryptedDmgBackend::open_with_recovery_key`](super::EncryptedDmgBackend::open_with_recovery_key)).
///
/// Same rules and guarantees as [`add_passphrase`].
#[cfg(feature = "dmg-encrypted-recovery")]
pub fn add_recipient<F: Read + Write + Seek + ?Sized>(
    image: &mut F,
    credential: Credential<'_>,
    recipient: &RecipientKey,
    rng: &mut dyn RandomSource,
) -> Result<usize> {
    add_record(image, credential, KEY_ENTRY_PUBLIC_KEY, |keyblob| {
        recipient.build_record(keyblob, rng)
    })
}

/// Remove key-table entry `index` and overwrite the record it points at
/// with zeros, proving with `passphrase` that the image stays openable.
/// See [`remove_key_record_with`].
pub fn remove_key_record<F: Read + Write + Seek + ?Sized>(
    image: &mut F,
    index: usize,
    passphrase: &str,
) -> Result<()> {
    remove_key_record_with(image, index, Credential::Passphrase(passphrase))
}

/// Remove key-table entry `index` and overwrite the record it points at
/// with zeros — `hdiutil erasekeys` for a single record.
///
/// To keep the image openable, `credential` must unlock a record **other
/// than** `index` (a passphrase record for a passphrase, a public-key
/// record for a recovery key); otherwise nothing is written. The entry is
/// dropped from the table first (later entries shift down one slot,
/// `key_count` shrinks), then the record's bytes are zeroed — unless
/// another entry's record overlaps them, in which case they are left
/// alone.
///
/// This invalidates the record in this file. It is **not** secure
/// erasure: copies of the image made before, file-system snapshots,
/// journaling and flash remapping can all retain it, and the content key
/// it wraps is unchanged — anyone who ever unwrapped it can still read the
/// payload.
pub fn remove_key_record_with<F: Read + Write + Seek + ?Sized>(
    image: &mut F,
    index: usize,
    credential: Credential<'_>,
) -> Result<()> {
    let (h, buf) = header_for_edit(image)?;
    let n = h.key_entries.len();
    if index >= n {
        return Err(crate::Error::InvalidArgument(format!(
            "encrcdsa: key record {index} does not exist ({n} records)"
        )));
    }
    if h.passphrase_keys.len() > MAX_PASSPHRASE_RECORDS {
        return Err(crate::Error::InvalidImage(format!(
            "encrcdsa: {} passphrase records exceed the maximum of {MAX_PASSPHRASE_RECORDS}",
            h.passphrase_keys.len()
        )));
    }
    // Lock-out guard: the credential must still open the image through
    // some other record.
    match super::unlock_with(&h, &buf, credential, Some(index), true) {
        Ok(_) => {}
        Err(crate::Error::Unsupported(_)) => {
            return Err(crate::Error::InvalidArgument(format!(
                "encrcdsa: the credential does not unlock any record other than {index}; \
                 refusing to remove it"
            )));
        }
        Err(e) => return Err(e),
    }

    // New table: the rows minus `index`, then one zeroed row where the
    // last one was.
    let mut table = Vec::with_capacity(4 + n * KEY_ENTRY_BYTES);
    table.extend_from_slice(&((n - 1) as u32).to_be_bytes());
    for (i, e) in h.key_entries.iter().enumerate() {
        if i == index {
            continue;
        }
        table.extend_from_slice(&e.kind.to_be_bytes());
        table.extend_from_slice(&e.offset.to_be_bytes());
        table.extend_from_slice(&e.size.to_be_bytes());
    }
    table.resize(4 + n * KEY_ENTRY_BYTES, 0);
    image.seek(SeekFrom::Start(ENCRCDSA_V2_HEADER_MIN_BYTES as u64 - 4))?;
    image.write_all(&table)?;

    let gone = &h.key_entries[index];
    let overlaps = h.key_entries.iter().enumerate().any(|(i, e)| {
        i != index && e.offset < gone.offset + gone.size && gone.offset < e.offset + e.size
    });
    if !overlaps {
        image.seek(SeekFrom::Start(gone.offset))?;
        image.write_all(&vec![0u8; gone.size as usize])?;
    }
    image.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::EncryptedDmgBackend;
    use super::*;
    use std::io::Cursor;

    /// Deterministic "RNG" for tests: a counter-driven byte stream.
    fn test_rng(seed: u8) -> impl FnMut(&mut [u8]) {
        let mut n = seed as u32;
        move |dest: &mut [u8]| {
            for b in dest {
                n = n.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                *b = (n >> 16) as u8;
            }
        }
    }

    fn opts(iters: u32) -> CreateOptions {
        CreateOptions {
            pbkdf2_iterations: iters,
            ..CreateOptions::default()
        }
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 31 + 7) ^ (i >> 5)) as u8).collect()
    }

    fn make(cipher: ContentCipher, payload: &[u8], pw: &str) -> Vec<u8> {
        let mut rng = test_rng(1);
        let keys = ContentKeys::generate(cipher, &mut rng);
        let mut out = Cursor::new(Vec::new());
        let r = create_encrypted_image(
            &mut out,
            &mut Cursor::new(payload),
            payload.len() as u64,
            pw,
            &keys,
            &opts(1000),
            &mut rng,
        )
        .unwrap();
        let v = out.into_inner();
        assert_eq!(r.image_len, v.len() as u64);
        assert_eq!(r.payload_len, payload.len() as u64);
        v
    }

    /// Open `bytes` with the crate's reader (which wants a path) and
    /// return the whole plaintext.
    fn decrypt(bytes: &[u8], pw: &str) -> Result<Vec<u8>> {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.dmg");
        std::fs::write(&p, bytes).unwrap();
        let mut be = EncryptedDmgBackend::open_with_password(&p, pw)?;
        let mut out = vec![0u8; be.total_size() as usize];
        be.read_at(0, &mut out)?;
        Ok(out)
    }

    #[test]
    fn create_round_trips_aes128_and_aes256() {
        // Not a multiple of 16 or of the chunk size: exercises the padded
        // trailing chunk the way hdiutil's compressed payloads do.
        let payload = pattern(512 * 9 + 77);
        for cipher in [ContentCipher::Aes128, ContentCipher::Aes256] {
            let img = make(cipher, &payload, "pässwörd");
            assert_eq!(&img[..8], ENCRCDSA_MAGIC);
            assert_eq!(img.len() as u64, ENCRYPTED_DATA_OFFSET + 512 * 10);
            assert_eq!(decrypt(&img, "pässwörd").unwrap(), payload, "{cipher:?}");
            let info = inspect_encrypted_image(&mut Cursor::new(&img)).unwrap();
            assert_eq!(info.cipher, Some(cipher));
            assert_eq!(info.key_bits, cipher.key_bits());
            assert_eq!(info.payload_len, payload.len() as u64);
            assert_eq!(info.chunk_size, 512);
            assert_eq!(info.key_records.len(), 1);
            let rec = &info.key_records[0];
            assert_eq!(rec.kind, KeyRecordKind::Passphrase);
            assert_eq!((rec.offset, rec.size), (0x60, 0x268));
            let p = rec.passphrase.as_ref().unwrap();
            assert_eq!(p.pbkdf2_iterations, 1000);
            assert_eq!(p.wrap_algorithm, algid::AES);
            assert_eq!(p.wrap_key_bits, 192);
            // key || hmac || "CKIE\0", PKCS#7-padded: 41 → 48, 57 → 64.
            assert_eq!(
                p.wrapped_keyblob_len,
                (cipher.key_len() + 25) / 16 * 16 + 16
            );
            assert!(info.kdf_within_limits());
            // The ciphertext is not the plaintext.
            assert!(!img.windows(64).any(|w| w == &payload[..64]));
        }
    }

    #[test]
    fn caller_supplied_keys_are_used() {
        let keys = ContentKeys::new(ContentCipher::Aes128, &[7u8; 16], &[9u8; 20]).unwrap();
        let payload = pattern(1024);
        let mut out = Cursor::new(Vec::new());
        let mut rng = test_rng(3);
        create_encrypted_image(
            &mut out,
            &mut Cursor::new(&payload),
            1024,
            "pw",
            &keys,
            &CreateOptions {
                pbkdf2_iterations: 10,
                uuid: Some(*b"0123456789abcdef"),
                ..CreateOptions::default()
            },
            &mut rng,
        )
        .unwrap();
        let img = out.into_inner();
        assert_eq!(&img[0x24..0x34], b"0123456789abcdef");
        // Chunk 0 is AES-128-CBC under the supplied key and HMAC-derived IV.
        let mut c0 = payload[..512].to_vec();
        aes_cbc_encrypt(&[7u8; 16], &chunk_iv(&[9u8; 20], 0), &mut c0).unwrap();
        let off = ENCRYPTED_DATA_OFFSET as usize;
        assert_eq!(&img[off..off + 512], &c0[..]);
        assert_eq!(decrypt(&img, "pw").unwrap(), payload);

        assert!(ContentKeys::new(ContentCipher::Aes256, &[0; 16], &[0; 20]).is_err());
        assert!(ContentKeys::new(ContentCipher::Aes128, &[0; 16], &[0; 19]).is_err());
    }

    #[test]
    fn deterministic_with_injected_rng() {
        let payload = pattern(700);
        let a = make(ContentCipher::Aes256, &payload, "pw");
        let b = make(ContentCipher::Aes256, &payload, "pw");
        assert_eq!(a, b);
    }

    #[test]
    fn from_device_matches_reader() {
        let payload = pattern(4096 + 512);
        let mut dev = crate::block::MemoryBackend::new(payload.len() as u64);
        dev.write_at(0, &payload).unwrap();
        let mut rng = test_rng(5);
        let keys = ContentKeys::generate(ContentCipher::Aes128, &mut rng);
        let mut out = Cursor::new(Vec::new());
        create_encrypted_image_from_device(&mut out, &mut dev, "pw", &keys, &opts(50), &mut rng)
            .unwrap();
        assert_eq!(decrypt(&out.into_inner(), "pw").unwrap(), payload);
    }

    #[test]
    fn wrong_password_fails() {
        let img = make(ContentCipher::Aes128, &pattern(512), "right");
        let err = decrypt(&img, "wrong").unwrap_err();
        assert!(matches!(err, crate::Error::Unsupported(_)), "{err:?}");
        let msg = format!("{err} {err:?}");
        assert!(!msg.contains("wrong\"") && !msg.contains("right"), "{msg}");
    }

    #[test]
    fn short_payload_fails_without_header() {
        let mut rng = test_rng(1);
        let keys = ContentKeys::generate(ContentCipher::Aes128, &mut rng);
        // A destination that already holds an image must not keep looking
        // like one after a failed run.
        let mut out = Cursor::new(make(ContentCipher::Aes128, &pattern(512), "x"));
        let err = create_encrypted_image(
            &mut out,
            &mut Cursor::new(vec![0u8; 100]),
            4096,
            "pw",
            &keys,
            &opts(10),
            &mut rng,
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidArgument(_)), "{err:?}");
        assert_ne!(&out.get_ref()[..8], ENCRCDSA_MAGIC);
    }

    #[test]
    fn bad_options_rejected_before_writing() {
        let mut rng = test_rng(1);
        let keys = ContentKeys::generate(ContentCipher::Aes128, &mut rng);
        for o in [
            opts(0),
            opts(MAX_PBKDF2_ITERATIONS + 1),
            CreateOptions {
                chunk_size: 100,
                ..opts(10)
            },
            CreateOptions {
                chunk_size: 0,
                ..opts(10)
            },
            CreateOptions {
                chunk_size: MAX_CHUNK_SIZE + 16,
                ..opts(10)
            },
        ] {
            let mut out = Cursor::new(Vec::new());
            let err = create_encrypted_image(
                &mut out,
                &mut Cursor::new(vec![0u8; 512]),
                512,
                "pw",
                &keys,
                &o,
                &mut rng,
            )
            .unwrap_err();
            assert!(
                matches!(err, crate::Error::InvalidArgument(_)),
                "{o:?}: {err:?}"
            );
            assert!(out.get_ref().is_empty(), "{o:?} wrote output");
        }
    }

    #[test]
    fn change_passphrase_keeps_payload() {
        let payload = pattern(512 * 4);
        for cipher in [ContentCipher::Aes128, ContentCipher::Aes256] {
            let before = make(cipher, &payload, "old");
            let mut img = Cursor::new(before.clone());
            let idx = change_passphrase(
                &mut img,
                "old",
                "new",
                &RekeyOptions {
                    pbkdf2_iterations: 2000,
                },
                &mut test_rng(9),
            )
            .unwrap();
            assert_eq!(idx, 0);
            let after = img.into_inner();
            assert_eq!(after.len(), before.len());
            // Only the key record changed.
            assert_eq!(&after[..0x60], &before[..0x60]);
            assert_eq!(&after[0x60 + 0x268..], &before[0x60 + 0x268..]);
            assert_ne!(&after[0x60..0x60 + 0x268], &before[0x60..0x60 + 0x268]);
            assert_eq!(decrypt(&after, "new").unwrap(), payload);
            assert!(matches!(
                decrypt(&after, "old").unwrap_err(),
                crate::Error::Unsupported(_)
            ));
            let info = inspect_encrypted_image(&mut Cursor::new(&after)).unwrap();
            assert_eq!(
                info.key_records[0]
                    .passphrase
                    .as_ref()
                    .unwrap()
                    .pbkdf2_iterations,
                2000
            );
        }
    }

    #[test]
    fn change_passphrase_wrong_old_writes_nothing() {
        let before = make(ContentCipher::Aes128, &pattern(512), "old");
        let mut img = Cursor::new(before.clone());
        let err = change_passphrase(
            &mut img,
            "nope",
            "new",
            &RekeyOptions::default(),
            &mut test_rng(9),
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Unsupported(_)), "{err:?}");
        assert_eq!(img.into_inner(), before);
    }

    /// Append a second key entry to `img`'s table, pointing at a copy of
    /// `record` placed at `at`. The table grows into the zeroed gap right
    /// after it, so the first record must be moved out of the way first
    /// by the caller (we just pick offsets past it).
    fn add_entry(img: &mut [u8], kind: u32, at: usize, record: &[u8]) {
        let n = u32::from_be_bytes(img[0x48..0x4C].try_into().unwrap()) as usize;
        // Move existing records? Our images keep record 0 at 0x60, right
        // where row 1 would go, so relocate it to 0x1000 first.
        if n == 1 {
            let off = u64::from_be_bytes(img[0x50..0x58].try_into().unwrap()) as usize;
            let size = u64::from_be_bytes(img[0x58..0x60].try_into().unwrap()) as usize;
            let rec = img[off..off + size].to_vec();
            img[off..off + size].fill(0);
            img[0x1000..0x1000 + size].copy_from_slice(&rec);
            img[0x50..0x58].copy_from_slice(&0x1000u64.to_be_bytes());
        }
        let row = ENCRCDSA_V2_HEADER_MIN_BYTES + n * KEY_ENTRY_BYTES;
        img[row..row + 4].copy_from_slice(&kind.to_be_bytes());
        img[row + 4..row + 12].copy_from_slice(&(at as u64).to_be_bytes());
        img[row + 12..row + 20].copy_from_slice(&(record.len() as u64).to_be_bytes());
        img[at..at + record.len()].copy_from_slice(record);
        img[0x48..0x4C].copy_from_slice(&((n + 1) as u32).to_be_bytes());
    }

    /// An image with two passphrase records (passphrases "a" and "b")
    /// plus an opaque record of unknown type 7.
    fn three_record_image(payload: &[u8]) -> Vec<u8> {
        let mut rng = test_rng(4);
        let keys = ContentKeys::generate(ContentCipher::Aes128, &mut rng);
        let mut out = Cursor::new(Vec::new());
        create_encrypted_image(
            &mut out,
            &mut Cursor::new(payload),
            payload.len() as u64,
            "a",
            &keys,
            &opts(100),
            &mut rng,
        )
        .unwrap();
        let mut img = out.into_inner();
        let rec_b = build_passphrase_record("b", &keys.keyblob().0, 100, 0x268, &mut rng).unwrap();
        add_entry(&mut img, KEY_ENTRY_PASSPHRASE, 0x2000, &rec_b);
        add_entry(&mut img, 7, 0x3000, &[0xC5; 0x300]);
        img
    }

    #[test]
    fn opaque_records_are_reported_and_preserved() {
        let payload = pattern(1024);
        let img = three_record_image(&payload);
        let info = inspect_encrypted_image(&mut Cursor::new(&img)).unwrap();
        let kinds: Vec<_> = info.key_records.iter().map(|r| r.kind).collect();
        assert_eq!(
            kinds,
            [
                KeyRecordKind::Passphrase,
                KeyRecordKind::Passphrase,
                KeyRecordKind::Other(7)
            ]
        );
        assert!(info.key_records[2].passphrase.is_none());
        assert_eq!(info.key_records[2].size, 0x300);
        assert_eq!(decrypt(&img, "a").unwrap(), payload);
        assert_eq!(decrypt(&img, "b").unwrap(), payload);

        // Rotating "b" rewrites record 1 only.
        let mut cur = Cursor::new(img.clone());
        let idx = change_passphrase(
            &mut cur,
            "b",
            "c",
            &RekeyOptions {
                pbkdf2_iterations: 100,
            },
            &mut test_rng(8),
        )
        .unwrap();
        assert_eq!(idx, 1);
        let rotated = cur.into_inner();
        assert_eq!(&rotated[..0x2000], &img[..0x2000]);
        assert_eq!(&rotated[0x2000 + 0x268..], &img[0x2000 + 0x268..]);
        assert_eq!(decrypt(&rotated, "a").unwrap(), payload);
        assert_eq!(decrypt(&rotated, "c").unwrap(), payload);
        assert!(decrypt(&rotated, "b").is_err());
    }

    #[test]
    fn remove_key_record_invalidates_and_guards_lockout() {
        let payload = pattern(1024);
        let img = three_record_image(&payload);

        // Removing record 0 with its own passphrase alone would be fine
        // only if "a" opened another record; it doesn't.
        let mut cur = Cursor::new(img.clone());
        let err = remove_key_record(&mut cur, 0, "a").unwrap_err();
        assert!(matches!(err, crate::Error::InvalidArgument(_)), "{err:?}");
        assert_eq!(cur.get_ref(), &img, "refused removal wrote nothing");
        assert!(remove_key_record(&mut cur, 9, "b").is_err());

        // Remove "a" (record 0) proving "b" still opens.
        remove_key_record(&mut cur, 0, "b").unwrap();
        let out = cur.into_inner();
        assert!(
            out[0x1000..0x1000 + 0x268].iter().all(|&b| b == 0),
            "record wiped"
        );
        let info = inspect_encrypted_image(&mut Cursor::new(&out)).unwrap();
        let kinds: Vec<_> = info.key_records.iter().map(|r| r.kind).collect();
        assert_eq!(kinds, [KeyRecordKind::Passphrase, KeyRecordKind::Other(7)]);
        assert_eq!(
            &out[0x3000..0x3300],
            &[0xC5; 0x300][..],
            "opaque record kept"
        );
        assert_eq!(decrypt(&out, "b").unwrap(), payload);
        assert!(matches!(
            decrypt(&out, "a").unwrap_err(),
            crate::Error::Unsupported(_)
        ));

        // The last passphrase record can't go.
        let mut cur = Cursor::new(out);
        let err = remove_key_record(&mut cur, 0, "b").unwrap_err();
        assert!(matches!(err, crate::Error::InvalidArgument(_)), "{err:?}");
        // The opaque one can, given a working passphrase.
        remove_key_record(&mut cur, 1, "b").unwrap();
        let out = cur.into_inner();
        let info = inspect_encrypted_image(&mut Cursor::new(&out)).unwrap();
        assert_eq!(info.key_records.len(), 1);
        assert_eq!(decrypt(&out, "b").unwrap(), payload);
    }

    #[test]
    fn huge_iteration_count_refused_without_work() {
        let mut img = make(ContentCipher::Aes128, &pattern(512), "pw");
        img[0x60 + 0x08..0x60 + 0x0C].copy_from_slice(&u32::MAX.to_be_bytes());
        let info = inspect_encrypted_image(&mut Cursor::new(&img)).unwrap();
        assert!(!info.kdf_within_limits());
        // If the cap didn't hold this would run 4 billion HMAC rounds.
        let err = decrypt(&img, "pw").unwrap_err();
        assert!(matches!(err, crate::Error::InvalidImage(_)), "{err:?}");
        let mut cur = Cursor::new(img.clone());
        let err = change_passphrase(
            &mut cur,
            "pw",
            "x",
            &RekeyOptions::default(),
            &mut test_rng(1),
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidImage(_)), "{err:?}");
        assert_eq!(cur.into_inner(), img);
    }

    #[test]
    fn malformed_headers_rejected_without_panic() {
        let good = make(ContentCipher::Aes128, &pattern(512), "pw");
        type Mutation = Box<dyn Fn(&mut Vec<u8>)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|b| b.truncate(0x30)),
            Box::new(|b| b.truncate(0x100)),
            Box::new(|b| b[0x48..0x4C].copy_from_slice(&1000u32.to_be_bytes())),
            Box::new(|b| b[0x50..0x58].copy_from_slice(&u64::MAX.to_be_bytes())),
            Box::new(|b| b[0x58..0x60].copy_from_slice(&(1u64 << 40).to_be_bytes())),
            Box::new(|b| b[0x60 + 0x64..0x60 + 0x68].copy_from_slice(&u32::MAX.to_be_bytes())),
            Box::new(|b| b[0x60 + 0x0C..0x60 + 0x10].copy_from_slice(&64u32.to_be_bytes())),
            Box::new(|b| b[0x38..0x40].copy_from_slice(&u64::MAX.to_be_bytes())),
            Box::new(|b| b[0x40..0x48].copy_from_slice(&u64::MAX.to_be_bytes())),
            Box::new(|b| b[0x34..0x38].copy_from_slice(&0u32.to_be_bytes())),
            Box::new(|b| b[0x34..0x38].copy_from_slice(&u32::MAX.to_be_bytes())),
            Box::new(|b| b[0x18..0x1C].copy_from_slice(&64u32.to_be_bytes())),
            // Record overlapping the payload.
            Box::new(|b| b[0x50..0x58].copy_from_slice(&ENCRYPTED_DATA_OFFSET.to_be_bytes())),
            // Keyblob that decrypts but whose padding is junk.
            Box::new(|b| b[0x60 + 0x68] ^= 0xFF),
        ];
        for (i, m) in mutations.iter().enumerate() {
            let mut img = good.clone();
            m(&mut img);
            // Each path must return (Ok or Err), never panic; the edits
            // must not change a byte when they fail.
            let _ = inspect_encrypted_image(&mut Cursor::new(&img));
            let _ = decrypt(&img, "pw");
            let mut cur = Cursor::new(img.clone());
            if change_passphrase(
                &mut cur,
                "pw",
                "x",
                &RekeyOptions {
                    pbkdf2_iterations: 10,
                },
                &mut test_rng(1),
            )
            .is_err()
            {
                assert_eq!(cur.get_ref(), &img, "mutation {i}: failed rotate wrote");
            }
        }
    }

    #[test]
    fn debug_output_is_redacted() {
        let keys = ContentKeys::new(ContentCipher::Aes128, &[0xAB; 16], &[0xCD; 20]).unwrap();
        let s = format!("{keys:?}");
        assert!(s.contains("redacted"), "{s}");
        assert!(
            !s.contains("171") && !s.contains("ab") && !s.contains("AB"),
            "{s}"
        );

        let img = make(ContentCipher::Aes128, &pattern(512), "pw");
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.dmg");
        std::fs::write(&p, &img).unwrap();
        let be = EncryptedDmgBackend::open_with_password(&p, "pw").unwrap();
        let s = format!("{be:?}");
        assert!(s.contains("redacted"), "{s}");
        // The keys `make` drew from test_rng(1).
        let k = ContentKeys::generate(ContentCipher::Aes128, &mut test_rng(1));
        assert!(!s.contains(&format!("{:?}", k.aes_key())), "{s}");
        assert!(!s.contains(&format!("{:?}", &k.hmac_key()[..])), "{s}");
    }

    /// A keyblob without the `CKIE` trailer still reads, but the
    /// in-place editors refuse it: padding alone cannot tell a wrong
    /// passphrase from a right one reliably enough to re-wrap.
    #[test]
    fn editors_require_keyblob_trailer() {
        let payload = pattern(1024);
        let mut rng = test_rng(6);
        let keys = ContentKeys::generate(ContentCipher::Aes128, &mut rng);
        let mut out = Cursor::new(Vec::new());
        create_encrypted_image(
            &mut out,
            &mut Cursor::new(&payload),
            1024,
            "pw",
            &keys,
            &opts(100),
            &mut rng,
        )
        .unwrap();
        let mut img = out.into_inner();
        let bare = [keys.aes_key(), &keys.hmac_key()[..]].concat();
        let rec = build_passphrase_record("pw", &bare, 100, 0x268, &mut rng).unwrap();
        img[0x60..0x60 + 0x268].copy_from_slice(&rec);

        assert_eq!(decrypt(&img, "pw").unwrap(), payload);
        let mut cur = Cursor::new(img.clone());
        let err = change_passphrase(
            &mut cur,
            "pw",
            "new",
            &RekeyOptions::default(),
            &mut test_rng(2),
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Unsupported(_)), "{err:?}");
        assert_eq!(cur.into_inner(), img);
    }

    fn rekey(iters: u32) -> RekeyOptions {
        RekeyOptions {
            pbkdf2_iterations: iters,
        }
    }

    fn create_with(payload: &[u8], protectors: &[Protector<'_>]) -> Result<Vec<u8>> {
        let mut rng = test_rng(11);
        let keys = ContentKeys::generate(ContentCipher::Aes256, &mut rng);
        let mut out = Cursor::new(Vec::new());
        create_encrypted_image_with(
            &mut out,
            &mut Cursor::new(payload),
            payload.len() as u64,
            protectors,
            &keys,
            &opts(100),
            &mut rng,
        )?;
        Ok(out.into_inner())
    }

    #[test]
    fn several_passphrases_at_creation_and_added_later() {
        let payload = pattern(2048);
        let img = create_with(
            &payload,
            &[Protector::Passphrase("one"), Protector::Passphrase("two")],
        )
        .unwrap();
        let info = inspect_encrypted_image(&mut Cursor::new(&img)).unwrap();
        assert_eq!(info.key_records.len(), 2);
        // Packed after a two-row table, as hdiutil lays out its records.
        assert_eq!(info.key_records[0].offset, 0x74);
        assert_eq!(info.key_records[1].offset, 0x74 + 0x268);
        assert_eq!(decrypt(&img, "one").unwrap(), payload);
        assert_eq!(decrypt(&img, "two").unwrap(), payload);

        // Add a third with the second.
        let mut cur = Cursor::new(img.clone());
        let idx = add_passphrase(
            &mut cur,
            Credential::Passphrase("two"),
            "three",
            &rekey(100),
            &mut test_rng(3),
        )
        .unwrap();
        assert_eq!(idx, 2);
        let grown = cur.into_inner();
        assert_eq!(grown.len(), img.len());
        assert_eq!(
            &grown[ENCRYPTED_DATA_OFFSET as usize..],
            &img[ENCRYPTED_DATA_OFFSET as usize..],
            "payload untouched"
        );
        let info = inspect_encrypted_image(&mut Cursor::new(&grown)).unwrap();
        let offs: Vec<_> = info.key_records.iter().map(|r| r.offset).collect();
        assert_eq!(offs, [0x88, 0x88 + 0x268, 0x88 + 2 * 0x268]);
        // Existing records moved byte-for-byte.
        assert_eq!(&grown[0x88..0x88 + 2 * 0x268], &img[0x74..0x74 + 2 * 0x268]);
        for pw in ["one", "two", "three"] {
            assert_eq!(decrypt(&grown, pw).unwrap(), payload, "{pw}");
        }

        // Wrong credential: nothing written.
        let mut cur = Cursor::new(img.clone());
        let err = add_passphrase(
            &mut cur,
            Credential::Passphrase("nope"),
            "x",
            &rekey(100),
            &mut test_rng(3),
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Unsupported(_)), "{err:?}");
        assert_eq!(cur.into_inner(), img);
    }

    #[test]
    fn protector_limits_enforced_before_writing() {
        let payload = pattern(512);
        let nine = [Protector::Passphrase("p"); MAX_PASSPHRASE_RECORDS + 1];
        assert!(matches!(
            create_with(&payload, &nine).unwrap_err(),
            crate::Error::InvalidArgument(_)
        ));
        assert!(matches!(
            create_with(&payload, &[]).unwrap_err(),
            crate::Error::InvalidArgument(_)
        ));
        // A full image takes no further passphrase.
        let eight = [Protector::Passphrase("p"); MAX_PASSPHRASE_RECORDS];
        let img = create_with(&payload, &eight).unwrap();
        let mut cur = Cursor::new(img.clone());
        let err = add_passphrase(
            &mut cur,
            Credential::Passphrase("p"),
            "q",
            &rekey(100),
            &mut test_rng(1),
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::InvalidArgument(_)), "{err:?}");
        assert_eq!(cur.into_inner(), img);
    }

    #[cfg(feature = "dmg-encrypted-recovery")]
    mod recovery {
        use super::super::super::{RecipientKey, RecoveryKey};
        use super::*;

        const CERT: &[u8] = include_bytes!("../testdata/recovery_cert.der");
        const KEY: &[u8] = include_bytes!("../testdata/recovery_key_pkcs1.der");
        const OTHER: &[u8] = include_bytes!("../testdata/other_key_pkcs1.der");

        fn decrypt_with_key(bytes: &[u8], key: &RecoveryKey) -> Result<Vec<u8>> {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("e.dmg");
            std::fs::write(&p, bytes).unwrap();
            let mut be = EncryptedDmgBackend::open_with_recovery_key(&p, key)?;
            let mut out = vec![0u8; be.total_size() as usize];
            be.read_at(0, &mut out)?;
            Ok(out)
        }

        #[test]
        fn create_with_certificate_and_passphrase() {
            let payload = pattern(3000);
            let cert = RecipientKey::from_certificate_der(CERT).unwrap();
            let key = RecoveryKey::from_der(KEY).unwrap();
            // hdiutil's order: certificate record first.
            let img = create_with(
                &payload,
                &[Protector::Recipient(&cert), Protector::Passphrase("pw")],
            )
            .unwrap();
            let info = inspect_encrypted_image(&mut Cursor::new(&img)).unwrap();
            assert_eq!(info.key_records.len(), 2);
            let r0 = &info.key_records[0];
            assert_eq!(r0.kind, KeyRecordKind::PublicKey);
            assert_eq!((r0.offset, r0.size), (0x74, 0x234));
            let pk = r0.public_key.as_ref().unwrap();
            assert_eq!(pk.key_id, cert.key_id());
            assert_eq!(pk.wrapped_keyblob_len, 256);
            assert!(pk.supported);
            assert_eq!(info.key_records[1].offset, 0x2A8);
            assert_eq!(decrypt(&img, "pw").unwrap(), payload);
            assert_eq!(decrypt_with_key(&img, &key).unwrap(), payload);
            let other = RecoveryKey::from_der(OTHER).unwrap();
            assert!(matches!(
                decrypt_with_key(&img, &other).unwrap_err(),
                crate::Error::Unsupported(_)
            ));
        }

        #[test]
        fn certificate_only_image_and_management_with_the_key() {
            let payload = pattern(1500);
            let cert = RecipientKey::from_certificate_der(CERT).unwrap();
            let key = RecoveryKey::from_der(KEY).unwrap();
            let img = create_with(&payload, &[Protector::Recipient(&cert)]).unwrap();
            assert_eq!(decrypt_with_key(&img, &key).unwrap(), payload);
            assert!(decrypt(&img, "").is_err());

            // The private key adds a passphrase…
            let mut cur = Cursor::new(img.clone());
            let idx = add_passphrase(
                &mut cur,
                Credential::RecoveryKey(&key),
                "late",
                &rekey(100),
                &mut test_rng(5),
            )
            .unwrap();
            assert_eq!(idx, 1);
            let img2 = cur.into_inner();
            assert_eq!(decrypt(&img2, "late").unwrap(), payload);
            assert_eq!(decrypt_with_key(&img2, &key).unwrap(), payload);

            // …which can then remove the certificate record (not the
            // other way round: the key can't remove its only record).
            let mut cur = Cursor::new(img2.clone());
            let err =
                remove_key_record_with(&mut cur, 0, Credential::RecoveryKey(&key)).unwrap_err();
            assert!(matches!(err, crate::Error::InvalidArgument(_)), "{err:?}");
            assert_eq!(cur.get_ref(), &img2);
            remove_key_record_with(&mut cur, 0, Credential::Passphrase("late")).unwrap();
            let img3 = cur.into_inner();
            assert!(matches!(
                decrypt_with_key(&img3, &key).unwrap_err(),
                crate::Error::Unsupported(_)
            ));
            assert_eq!(decrypt(&img3, "late").unwrap(), payload);
        }

        #[test]
        fn add_recipient_to_passphrase_image() {
            let payload = pattern(4096);
            let img = make(ContentCipher::Aes128, &payload, "pw");
            let cert = RecipientKey::from_certificate_der(CERT).unwrap();
            let key = RecoveryKey::from_der(KEY).unwrap();

            // Wrong passphrase: refused, nothing written.
            let mut cur = Cursor::new(img.clone());
            let err = add_recipient(
                &mut cur,
                Credential::Passphrase("no"),
                &cert,
                &mut test_rng(2),
            )
            .unwrap_err();
            assert!(matches!(err, crate::Error::Unsupported(_)), "{err:?}");
            assert_eq!(cur.get_ref(), &img);

            let idx = add_recipient(
                &mut cur,
                Credential::Passphrase("pw"),
                &cert,
                &mut test_rng(2),
            )
            .unwrap();
            assert_eq!(idx, 1);
            let out = cur.into_inner();
            assert_eq!(decrypt(&out, "pw").unwrap(), payload);
            assert_eq!(decrypt_with_key(&out, &key).unwrap(), payload);
            // The passphrase record moved from 0x60 to 0x74; nothing of it
            // is left behind past the new layout.
            let info = inspect_encrypted_image(&mut Cursor::new(&out)).unwrap();
            assert_eq!(info.key_records[0].offset, 0x74);
            assert_eq!(info.key_records[1].offset, 0x74 + 0x268);
            assert_eq!(&out[0x74..0x74 + 0x268], &img[0x60..0x60 + 0x268]);
            assert!(
                out[0x74 + 0x268 + 0x234..ENCRYPTED_DATA_OFFSET as usize]
                    .iter()
                    .all(|&b| b == 0)
            );

            // A second recipient, added with the first's private key.
            let other = RecoveryKey::from_der(OTHER).unwrap();
            let mut cur = Cursor::new(out);
            add_recipient(
                &mut cur,
                Credential::RecoveryKey(&key),
                &other.recipient(),
                &mut test_rng(4),
            )
            .unwrap();
            let out = cur.into_inner();
            assert_eq!(decrypt_with_key(&out, &other).unwrap(), payload);
            assert_eq!(decrypt_with_key(&out, &key).unwrap(), payload);
            assert_eq!(decrypt(&out, "pw").unwrap(), payload);
        }
    }
}
