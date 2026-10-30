//! Public-key (certificate) recovery records (`dmg-encrypted-recovery`
//! feature).
//!
//! `hdiutil create -certificate cert.cer` adds a second key record to an
//! encrypted image: the same keyblob a passphrase record wraps, encrypted
//! with RSAES-PKCS1-v1_5 to the certificate's RSA public key and tagged
//! with the SHA-1 of that key (see [`PublicKeyRecord`] for the layout).
//! Whoever holds the matching private key can open the image without the
//! passphrase — `hdiutil attach -recover <keychain>`.
//!
//! This module holds the two key types:
//!
//! - [`RecipientKey`] — a certificate's (or bare) RSA public key, to add a
//!   recovery record for;
//! - [`RecoveryKey`] — the private key that opens such a record.
//!
//! Both are parsed from caller-supplied DER/PEM bytes; nothing here looks
//! in a keychain or prompts.
//!
//! ## Security notes
//!
//! - RSA decryption uses PKCS#1 v1.5 **implicit rejection**: a record that
//!   does not decrypt under the key yields a pseudo-random plaintext of the
//!   expected length instead of an error, so success and padding failure
//!   are indistinguishable from the outside (no Bleichenbacher oracle). The
//!   record then counts as unlocked only when that plaintext ends in the
//!   `"CKIE" 0x00` trailer `hdiutil` puts after the keys — a 40-bit check
//!   on top of the 2^-(8·k) odds of a forged ciphertext decoding at all.
//! - Key sizes are bounded to [`MIN_RECOVERY_KEY_BITS`] ..=
//!   [`MAX_RECOVERY_KEY_BITS`] on both sides: the upper bound is what the
//!   record's 512-byte blob buffer holds and caps the cost of the private
//!   operation; images name at most [`MAX_PUBLIC_KEY_RECORDS`] records per
//!   key.
//! - [`RecoveryKey`] keeps the private key in `purecrypto`'s
//!   `BoxedRsaPrivateKey`, which wipes its secret limbs on drop; its
//!   `Debug` shows only the key id and size. Parse errors never quote the
//!   input.
//!
//! [`PublicKeyRecord`]: super::PublicKeyRecord
//! [`MAX_PUBLIC_KEY_RECORDS`]: super::MAX_PUBLIC_KEY_RECORDS

use purecrypto::rsa::{BoxedRsaPrivateKey, BoxedRsaPublicKey};

use crate::Result;

#[cfg(feature = "dmg-encrypted-write")]
use super::PUBLIC_KEY_RECORD_FIXED_BYTES;
use super::{
    EncryptedDmgHeader, KEYBLOB_TRAILER, MAX_PUBLIC_KEY_RECORDS, PUBLIC_KEY_PADDING_PKCS1,
    SecretBytes, algid, public_key_records,
};

/// Smallest RSA modulus accepted for a recipient or recovery key, in bits.
pub const MIN_RECOVERY_KEY_BITS: usize = 1024;

/// Largest RSA modulus accepted, in bits: the 512-byte keyblob buffer of
/// the record `hdiutil` lays out holds a 4096-bit ciphertext and no more.
pub const MAX_RECOVERY_KEY_BITS: usize = 4096;

/// Size of a public-key record as `hdiutil` lays it out: the fixed part
/// plus a 512-byte blob buffer.
#[cfg(feature = "dmg-encrypted-write")]
pub(crate) const PUBLIC_KEY_RECORD_BYTES: usize = PUBLIC_KEY_RECORD_FIXED_BYTES + 512;

/// Length of the key id: a SHA-1.
const KEY_ID_LEN: usize = 20;

fn der_err(what: &str, e: purecrypto::der::Error) -> crate::Error {
    // `der::Error` describes the structure, never the bytes.
    crate::Error::InvalidArgument(format!("encrcdsa: {what}: {e}"))
}

fn check_bits(bits: usize) -> Result<()> {
    if !(MIN_RECOVERY_KEY_BITS..=MAX_RECOVERY_KEY_BITS).contains(&bits) {
        return Err(crate::Error::InvalidArgument(format!(
            "encrcdsa: {bits}-bit RSA key outside the supported \
             {MIN_RECOVERY_KEY_BITS}..={MAX_RECOVERY_KEY_BITS} bits"
        )));
    }
    Ok(())
}

/// SHA-1 of the PKCS#1 `RSAPublicKey` DER — the id public-key records
/// carry (and `hdiutil -pubkey` takes in hex).
fn key_id_of(key: &BoxedRsaPublicKey) -> [u8; KEY_ID_LEN] {
    purecrypto::hash::sha1(&key.to_pkcs1_der())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Pull the `SubjectPublicKeyInfo` out of a DER X.509 certificate,
/// without interpreting anything else in it (validity, issuer, extensions
/// and signature are irrelevant to a recovery record).
fn certificate_spki(der: &[u8]) -> std::result::Result<&[u8], purecrypto::der::Error> {
    use purecrypto::der::Reader;
    let mut outer = Reader::new(der);
    let mut cert = outer.read_sequence()?;
    let mut tbs = cert.read_sequence()?;
    // version [0] EXPLICIT, optional.
    if tbs.peek_tag() == Some(0xA0) {
        tbs.read_any()?;
    }
    tbs.read_integer_bytes()?; // serialNumber
    tbs.read_sequence()?; // signature AlgorithmIdentifier
    tbs.read_sequence()?; // issuer
    tbs.read_sequence()?; // validity
    tbs.read_sequence()?; // subject
    tbs.read_element() // subjectPublicKeyInfo
}

/// An RSA public key to add a recovery record for: what
/// `hdiutil create -certificate` takes.
///
/// Only RSA keys of [`MIN_RECOVERY_KEY_BITS`] ..= [`MAX_RECOVERY_KEY_BITS`]
/// bits are accepted. The certificate itself is not validated (expiry,
/// chain, key usage): `hdiutil` doesn't either, and only the key matters
/// to the record.
#[derive(Clone)]
#[non_exhaustive]
pub struct RecipientKey {
    // Only encrypted to with `dmg-encrypted-write`; without it the type
    // still identifies a key (`key_id`).
    #[cfg_attr(not(feature = "dmg-encrypted-write"), allow(dead_code))]
    key: BoxedRsaPublicKey,
    key_id: [u8; KEY_ID_LEN],
    bits: usize,
}

impl RecipientKey {
    fn from_key(key: BoxedRsaPublicKey) -> Result<Self> {
        let bits = key.modulus().bit_len();
        check_bits(bits)?;
        Ok(Self {
            key_id: key_id_of(&key),
            key,
            bits,
        })
    }

    /// The public key of a DER-encoded X.509 certificate (`.cer`, as
    /// `hdiutil -certificate` wants it).
    pub fn from_certificate_der(der: &[u8]) -> Result<Self> {
        let spki = certificate_spki(der).map_err(|e| der_err("certificate", e))?;
        Self::from_spki_der(spki)
    }

    /// The public key of a PEM `CERTIFICATE`.
    pub fn from_certificate_pem(pem: &str) -> Result<Self> {
        let der = purecrypto::der::pem_decode(pem, "CERTIFICATE")
            .map_err(|e| der_err("certificate PEM", e))?;
        Self::from_certificate_der(&der)
    }

    /// A DER `SubjectPublicKeyInfo` holding an RSA key.
    pub fn from_spki_der(der: &[u8]) -> Result<Self> {
        Self::from_key(
            BoxedRsaPublicKey::from_spki_der(der).map_err(|e| der_err("RSA public key", e))?,
        )
    }

    /// A DER PKCS#1 `RSAPublicKey`.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        Self::from_key(
            BoxedRsaPublicKey::from_pkcs1_der(der).map_err(|e| der_err("RSA public key", e))?,
        )
    }

    /// The key id public-key records carry: SHA-1 of the PKCS#1
    /// `RSAPublicKey` DER. In hex, it is what `hdiutil create -pubkey`
    /// takes.
    pub fn key_id(&self) -> [u8; 20] {
        self.key_id
    }

    /// Modulus size in bits.
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// Encrypt `keyblob` to this key with RSAES-PKCS1-v1_5 and lay it out
    /// as a public-key record of [`PUBLIC_KEY_RECORD_BYTES`].
    #[cfg(feature = "dmg-encrypted-write")]
    pub(crate) fn build_record(
        &self,
        keyblob: &[u8],
        rng: &mut dyn super::RandomSource,
    ) -> Result<Vec<u8>> {
        let ct = self
            .key
            .encrypt_pkcs1v15(keyblob, &mut RngAdapter(rng))
            .map_err(|e| crate::Error::InvalidArgument(format!("encrcdsa: RSA encrypt: {e}")))?;
        // `check_bits` capped the modulus at 4096 bits = 512 bytes.
        debug_assert!(PUBLIC_KEY_RECORD_FIXED_BYTES + ct.len() <= PUBLIC_KEY_RECORD_BYTES);
        let mut rec = vec![0u8; PUBLIC_KEY_RECORD_BYTES];
        let put =
            |rec: &mut [u8], at: usize, v: u32| rec[at..at + 4].copy_from_slice(&v.to_be_bytes());
        put(&mut rec, 0x00, KEY_ID_LEN as u32);
        rec[0x04..0x04 + KEY_ID_LEN].copy_from_slice(&self.key_id);
        put(&mut rec, 0x24, algid::RSA);
        put(&mut rec, 0x28, PUBLIC_KEY_PADDING_PKCS1);
        put(&mut rec, 0x2C, 0);
        put(&mut rec, 0x30, ct.len() as u32);
        rec[PUBLIC_KEY_RECORD_FIXED_BYTES..PUBLIC_KEY_RECORD_FIXED_BYTES + ct.len()]
            .copy_from_slice(&ct);
        Ok(rec)
    }
}

impl std::fmt::Debug for RecipientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipientKey")
            .field("key_id", &hex(&self.key_id))
            .field("bits", &self.bits)
            .finish_non_exhaustive()
    }
}

/// The RSA private key of a recovery certificate: opens the public-key
/// records made for its public half.
///
/// Parsed from caller-supplied DER or PEM (PKCS#1 `RSA PRIVATE KEY` or
/// unencrypted PKCS#8 `PRIVATE KEY`); exporting it from a keychain or a
/// `.p12` is the caller's business. The key material is wiped on drop and
/// never appears in `Debug` output or error messages.
#[non_exhaustive]
pub struct RecoveryKey {
    key: BoxedRsaPrivateKey,
    key_id: [u8; KEY_ID_LEN],
    bits: usize,
}

impl RecoveryKey {
    fn from_key(key: BoxedRsaPrivateKey) -> Result<Self> {
        let public = key.public_key();
        let bits = public.modulus().bit_len();
        check_bits(bits)?;
        Ok(Self {
            key_id: key_id_of(&public),
            key,
            bits,
        })
    }

    /// A DER PKCS#1 `RSAPrivateKey` (`openssl rsa -traditional -outform
    /// DER`).
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        Self::from_key(
            BoxedRsaPrivateKey::from_pkcs1_der(der).map_err(|e| der_err("RSA private key", e))?,
        )
    }

    /// A DER unencrypted PKCS#8 `PrivateKeyInfo` holding an RSA key.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        Self::from_key(
            BoxedRsaPrivateKey::from_pkcs8_der(der).map_err(|e| der_err("RSA private key", e))?,
        )
    }

    /// DER in either form: PKCS#8 is tried first, then PKCS#1.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        Self::from_pkcs8_der(der).or_else(|_| Self::from_pkcs1_der(der))
    }

    /// A PEM `PRIVATE KEY` (PKCS#8) or `RSA PRIVATE KEY` (PKCS#1)
    /// document. Encrypted PEM is not accepted.
    pub fn from_pem(pem: &str) -> Result<Self> {
        if let Ok(der) = purecrypto::der::pem_decode(pem, "PRIVATE KEY") {
            let der = SecretBytes(der);
            return Self::from_pkcs8_der(&der.0);
        }
        let der = purecrypto::der::pem_decode(pem, "RSA PRIVATE KEY")
            .map_err(|e| der_err("private key PEM", e))?;
        let der = SecretBytes(der);
        Self::from_pkcs1_der(&der.0)
    }

    /// The id of the public half — the key id of the records this key
    /// opens (see [`RecipientKey::key_id`]).
    pub fn key_id(&self) -> [u8; 20] {
        self.key_id
    }

    /// Modulus size in bits.
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// The public half, to add records for this same key.
    pub fn recipient(&self) -> RecipientKey {
        RecipientKey {
            key: self.key.public_key(),
            key_id: self.key_id,
            bits: self.bits,
        }
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryKey")
            .field("key_id", &hex(&self.key_id))
            .field("bits", &self.bits)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// Bridge a [`RandomSource`](super::RandomSource) to `purecrypto`'s RNG
/// traits for the PKCS#1 padding bytes.
#[cfg(feature = "dmg-encrypted-write")]
struct RngAdapter<'a>(&'a mut dyn super::RandomSource);

#[cfg(feature = "dmg-encrypted-write")]
impl purecrypto::rng::RngCore for RngAdapter<'_> {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_random(dest);
    }
}

// The caller vouches for its source the way `RandomSource` documents.
#[cfg(feature = "dmg-encrypted-write")]
impl purecrypto::rng::CryptoRng for RngAdapter<'_> {}

/// Try `key` against the public-key records naming its id, in table
/// order, skipping key-table index `skip`. Returns the index of the first
/// record that unlocks and the keyblob plaintext
/// (`aes_key || hmac_key || "CKIE" 0x00`).
///
/// Fails with [`crate::Error::Unsupported`] when no record unlocks — the
/// "wrong key" signal, as for a wrong passphrase.
pub(crate) fn unlock_public_key(
    header: &EncryptedDmgHeader,
    buf: &[u8],
    key: &RecoveryKey,
    skip: Option<usize>,
) -> Result<(usize, SecretBytes)> {
    let aes_key_len = header.aes_key_len()?;
    let expected = aes_key_len + 20 + KEYBLOB_TRAILER.len();
    let modulus_len = key.bits.div_ceil(8);
    let mut attempts = 0usize;
    let mut last_err = None;
    for (index, rec) in public_key_records(header, buf) {
        if Some(index) == skip {
            continue;
        }
        let rec = match rec {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        if rec.key_id() != key.key_id {
            continue;
        }
        attempts += 1;
        if attempts > MAX_PUBLIC_KEY_RECORDS {
            return Err(crate::Error::InvalidImage(format!(
                "encrcdsa: more than {MAX_PUBLIC_KEY_RECORDS} public-key records name this key"
            )));
        }
        if rec.wrap_algorithm != algid::RSA || rec.wrap_padding != PUBLIC_KEY_PADDING_PKCS1 {
            last_err = Some(crate::Error::Unsupported(format!(
                "encrcdsa: public-key record {index} uses wrap algorithm {:#x} / padding {}; \
                 only RSA with PKCS#1 v1.5 padding is supported",
                rec.wrap_algorithm, rec.wrap_padding
            )));
            continue;
        }
        if rec.wrapped_keyblob.len() != modulus_len {
            last_err = Some(crate::Error::InvalidImage(format!(
                "encrcdsa: public-key record {index} holds a {}-byte ciphertext, the key's \
                 modulus is {modulus_len} bytes",
                rec.wrapped_keyblob.len()
            )));
            continue;
        }
        // Implicit rejection: a bad ciphertext yields synthetic bytes of
        // the expected length, which the trailer check then rejects.
        let plain = SecretBytes(
            key.key
                .decrypt_pkcs1v15_session(&rec.wrapped_keyblob, expected)
                .map_err(|e| crate::Error::InvalidImage(format!("encrcdsa: RSA decrypt: {e}")))?,
        );
        if plain.0.len() == expected
            && plain.0[expected - KEYBLOB_TRAILER.len()..] == KEYBLOB_TRAILER[..]
        {
            return Ok((index, plain));
        }
        last_err = Some(crate::Error::Unsupported(format!(
            "encrcdsa: public-key record {index} does not unlock with this key"
        )));
    }
    Err(last_err.unwrap_or_else(|| {
        crate::Error::Unsupported(format!(
            "encrcdsa: no public-key record for key id {}",
            hex(&key.key_id)
        ))
    }))
}

#[cfg(test)]
mod tests {
    use super::super::{EncryptedDmgBackend, KEY_ENTRY_PUBLIC_KEY, PublicKeyRecord};
    use super::*;
    use crate::block::BlockDevice;

    const IMG: &[u8] = include_bytes!("../testdata/encrcdsa_aes256_cert_fat12_hunter2.dmg");
    const CERT: &[u8] = include_bytes!("../testdata/recovery_cert.der");
    const KEY1: &[u8] = include_bytes!("../testdata/recovery_key_pkcs1.der");
    const KEY8: &[u8] = include_bytes!("../testdata/recovery_key_pkcs8.der");
    const OTHER: &[u8] = include_bytes!("../testdata/other_key_pkcs1.der");

    /// The certificate's Subject Key Identifier, which `openssl` computes
    /// the same way `hdiutil` computes the record's key id.
    const CERT_KEY_ID: [u8; 20] = [
        0x2c, 0x0a, 0x8b, 0x6f, 0xa8, 0x3c, 0xc0, 0x4f, 0x89, 0xd4, 0xbd, 0x73, 0x92, 0xf9, 0xd9,
        0x2b, 0xcd, 0xe5, 0xad, 0xa6,
    ];

    fn open(bytes: &[u8], key: &RecoveryKey) -> Result<EncryptedDmgBackend> {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e.dmg");
        std::fs::write(&p, bytes).unwrap();
        EncryptedDmgBackend::open_with_recovery_key(&p, key)
    }

    #[test]
    fn keys_parse_and_share_the_hdiutil_key_id() {
        let r = RecipientKey::from_certificate_der(CERT).unwrap();
        let k1 = RecoveryKey::from_pkcs1_der(KEY1).unwrap();
        let k8 = RecoveryKey::from_pkcs8_der(KEY8).unwrap();
        assert_eq!(r.key_id(), CERT_KEY_ID);
        assert_eq!(k1.key_id(), CERT_KEY_ID);
        assert_eq!(k8.key_id(), CERT_KEY_ID);
        assert_eq!(k1.recipient().key_id(), CERT_KEY_ID);
        assert_eq!((r.bits(), k1.bits()), (2048, 2048));
        assert_eq!(RecoveryKey::from_der(KEY1).unwrap().key_id(), CERT_KEY_ID);
        assert_eq!(RecoveryKey::from_der(KEY8).unwrap().key_id(), CERT_KEY_ID);
        let pem = purecrypto::der::pem_encode("CERTIFICATE", CERT);
        assert_eq!(
            RecipientKey::from_certificate_pem(&pem).unwrap().key_id(),
            CERT_KEY_ID
        );
        let pem = purecrypto::der::pem_encode("PRIVATE KEY", KEY8);
        assert_eq!(RecoveryKey::from_pem(&pem).unwrap().key_id(), CERT_KEY_ID);
        let pem = purecrypto::der::pem_encode("RSA PRIVATE KEY", KEY1);
        assert_eq!(RecoveryKey::from_pem(&pem).unwrap().key_id(), CERT_KEY_ID);

        // Garbage and truncation are clean errors.
        assert!(RecipientKey::from_certificate_der(&CERT[..100]).is_err());
        assert!(RecoveryKey::from_der(&KEY1[..200]).is_err());
        assert!(RecoveryKey::from_der(b"not a key").is_err());
        assert!(RecipientKey::from_certificate_der(KEY1).is_err());
    }

    #[test]
    fn oversized_keys_are_refused() {
        use purecrypto::der::{encode_integer, encode_sequence};
        // An 8192-bit "modulus" (odd, top bit set) with e = 65537.
        let mut n = vec![0xC3u8; 1024];
        n[1023] |= 1;
        let der = encode_sequence(&[encode_integer(&n), encode_integer(&[1, 0, 1])].concat());
        let err = RecipientKey::from_pkcs1_der(&der).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidArgument(_)), "{err:?}");
        assert!(err.to_string().contains("8192-bit"), "{err}");
    }

    #[test]
    fn debug_never_shows_private_key() {
        let k = RecoveryKey::from_pkcs1_der(KEY1).unwrap();
        let s = format!("{k:?}");
        assert!(s.contains("redacted"), "{s}");
        assert!(s.contains("2c0a8b6f"), "{s}");
        // No limb dump of any kind.
        assert!(s.len() < 200, "{s}");
        let c = super::super::Credential::RecoveryKey(&k);
        assert!(format!("{c:?}").len() < 250);
        let p = super::super::Credential::Passphrase("hunter2");
        assert!(!format!("{p:?}").contains("hunter2"));
    }

    /// `hdiutil create -encryption AES-256 -certificate recovery_cert.der
    /// -stdinpass` (passphrase `hunter2`) over a 64 KiB FAT12 volume:
    /// the private key alone opens it.
    #[test]
    fn hdiutil_certificate_image_opens_with_private_key() {
        let h = super::super::EncryptedDmgHeader::decode(IMG).unwrap();
        assert_eq!(h.key_entries.len(), 2);
        assert_eq!(h.key_entries[0].kind, KEY_ENTRY_PUBLIC_KEY);
        assert_eq!(
            (h.key_entries[0].offset, h.key_entries[0].size),
            (0x74, 0x234)
        );
        let rec = PublicKeyRecord::decode(&IMG[0x74..0x74 + 0x234]).unwrap();
        assert_eq!(rec.key_id(), CERT_KEY_ID);
        assert_eq!(rec.wrap_algorithm, algid::RSA);
        assert_eq!(rec.wrap_padding, PUBLIC_KEY_PADDING_PKCS1);
        assert_eq!(rec.wrap_mode, 0);
        assert_eq!(rec.wrapped_keyblob.len(), 256);

        for key in [
            RecoveryKey::from_pkcs1_der(KEY1).unwrap(),
            RecoveryKey::from_pkcs8_der(KEY8).unwrap(),
        ] {
            let mut be = open(IMG, &key).unwrap();
            assert_eq!(be.total_size(), 64 * 1024);
            let mut boot = vec![0u8; 512];
            be.read_at(0, &mut boot).unwrap();
            assert_eq!(&boot[510..512], &[0x55, 0xAA]);
            assert_eq!(&boot[0x36..0x3E], b"FAT12   ");
            assert_eq!(&boot[0x2B..0x2F], b"CERT");
        }
    }

    #[test]
    fn wrong_or_damaged_key_material_fails_cleanly() {
        let other = RecoveryKey::from_pkcs1_der(OTHER).unwrap();
        let err = open(IMG, &other).unwrap_err();
        assert!(matches!(err, crate::Error::Unsupported(_)), "{err:?}");

        // A record re-labelled with the other key's id: the RSA decrypt
        // runs, implicit rejection yields junk, the trailer check refuses.
        let mut img = IMG.to_vec();
        img[0x74 + 4..0x74 + 24].copy_from_slice(&other.key_id());
        let err = open(&img, &other).unwrap_err();
        assert!(matches!(err, crate::Error::Unsupported(_)), "{err:?}");

        // Damaged ciphertext, right key.
        let key = RecoveryKey::from_pkcs1_der(KEY1).unwrap();
        let mut img = IMG.to_vec();
        img[0x74 + 0x34 + 100] ^= 0x40;
        let err = open(&img, &key).unwrap_err();
        assert!(matches!(err, crate::Error::Unsupported(_)), "{err:?}");

        // Hostile lengths and ids: errors, never panics.
        type Mutation = fn(&mut Vec<u8>);
        let mutations: [Mutation; 5] = [
            |b| b[0x74 + 0x30..0x74 + 0x34].copy_from_slice(&u32::MAX.to_be_bytes()),
            |b| b[0x74 + 0x30..0x74 + 0x34].copy_from_slice(&255u32.to_be_bytes()),
            |b| b[0x74..0x78].copy_from_slice(&33u32.to_be_bytes()),
            |b| b[0x74 + 0x24..0x74 + 0x28].copy_from_slice(&7u32.to_be_bytes()),
            |b| b[0x58..0x60].copy_from_slice(&0x20u64.to_be_bytes()),
        ];
        for m in mutations {
            let mut img = IMG.to_vec();
            m(&mut img);
            let r = open(&img, &key);
            assert!(r.is_err());
        }
    }

    /// A header naming one key in more public-key records than the cap
    /// is refused rather than costing that many RSA operations.
    #[test]
    fn public_key_attempts_are_bounded() {
        let key = RecoveryKey::from_pkcs1_der(KEY1).unwrap();
        let mut img = IMG.to_vec();
        let n = MAX_PUBLIC_KEY_RECORDS + 1;
        // Every row points at the same damaged (so never unlocking)
        // public-key record, moved past the grown table.
        let mut rec = img[0x74..0x74 + 0x234].to_vec();
        rec[0x34 + 7] ^= 1;
        img[0x48..0x1000].fill(0);
        img[0x48..0x4C].copy_from_slice(&(n as u32).to_be_bytes());
        for i in 0..n {
            let row = 0x4C + i * 20;
            img[row..row + 4].copy_from_slice(&KEY_ENTRY_PUBLIC_KEY.to_be_bytes());
            img[row + 4..row + 12].copy_from_slice(&0x1000u64.to_be_bytes());
            img[row + 12..row + 20].copy_from_slice(&0x234u64.to_be_bytes());
        }
        img[0x1000..0x1234].copy_from_slice(&rec);
        let err = open(&img, &key).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidImage(_)), "{err:?}");
        assert!(err.to_string().contains("more than"), "{err}");
    }
}
