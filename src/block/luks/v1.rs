//! LUKS1 — the original on-disk format.
//!
//! Everything LUKS1 knows lives in one 592-byte big-endian header at
//! offset 0, followed by up to eight keyslots' worth of key material and
//! then the encrypted payload:
//!
//! ```text
//!   0                  phdr (592 bytes, big-endian)
//!   4096               keyslot 0 key material  (stripes × key_bytes)
//!   …                  keyslot 1 … 7, each 4096-aligned
//!   payload_offset×512 encrypted payload
//! ```
//!
//! ## phdr layout
//!
//! ```text
//!     0   6  magic            "LUKS\xba\xbe"
//!     6   2  version          1
//!     8  32  cipher-name      "aes"
//!    40  32  cipher-mode      "xts-plain64"
//!    72  32  hash-spec        "sha256"
//!   104   4  payload-offset   in 512-byte sectors
//!   108   4  key-bytes        master-key length
//!   112  20  mk-digest        PBKDF2 of the master key
//!   132  32  mk-digest-salt
//!   164   4  mk-digest-iter
//!   168  40  uuid             ASCII, NUL-padded
//!   208 384  8 × keyslot (48 bytes each)
//! ```
//!
//! Each keyslot is:
//!
//! ```text
//!     0   4  active               0x00AC71F3 enabled / 0x0000DEAD disabled
//!     4   4  iterations           PBKDF2 rounds for this passphrase
//!     8  32  salt
//!    40   4  key-material-offset  in 512-byte sectors
//!    44   4  stripes              anti-forensic stripe count (4000)
//! ```
//!
//! ## Opening a slot
//!
//! `PBKDF2(passphrase, slot.salt, slot.iterations)` gives a key that
//! decrypts the slot's key material with the volume's own cipher, sector
//! indices counted from 0 at the start of the material.
//! [`super::af::merge`] collapses the stripes back to a master-key
//! candidate, and the candidate is accepted only if
//! `PBKDF2(candidate, mk_digest_salt, mk_digest_iter)` reproduces the
//! stored 20-byte `mk-digest`. A wrong passphrase fails that check.

use purecrypto::hash::HashAlgorithm;

use crate::Result;

use super::af;
use super::crypt::{CipherSpec, SectorCipher};
use super::hash;

/// Six-byte magic at offset 0 — shared with LUKS2, which differs only in
/// the version field that follows.
pub const LUKS_MAGIC: [u8; 6] = [b'L', b'U', b'K', b'S', 0xba, 0xbe];

/// Total size of the LUKS1 phdr, keyslot array included.
pub const PHDR_BYTES: usize = 592;

/// Number of keyslots. Fixed by the format.
pub const NUM_KEYS: usize = 8;

/// `mk-digest` is a fixed 20 bytes regardless of the hash — LUKS1 predates
/// the idea of a variable digest field, and cryptsetup truncates longer
/// hashes to fit.
pub const DIGEST_BYTES: usize = 20;

/// Salt fields are a fixed 32 bytes.
pub const SALT_BYTES: usize = 32;

/// Keyslot `active` marker: this slot holds usable key material.
pub const SLOT_ENABLED: u32 = 0x00AC_71F3;
/// Keyslot `active` marker: this slot is empty.
pub const SLOT_DISABLED: u32 = 0x0000_DEAD;

/// Keyslots and the payload both start on a 4096-byte boundary.
pub const KEYSLOT_ALIGN: u64 = 4096;

/// One of the eight keyslots.
#[derive(Debug, Clone, Copy)]
pub struct KeySlot {
    /// Raw `active` marker as found on disk.
    pub active: u32,
    /// PBKDF2 rounds applied to the passphrase for this slot.
    pub iterations: u32,
    pub salt: [u8; SALT_BYTES],
    /// Start of this slot's key material, in 512-byte sectors.
    pub key_material_offset: u32,
    /// Anti-forensic stripe count (4000 in every cryptsetup-made header).
    pub stripes: u32,
}

impl KeySlot {
    /// True when the slot holds key material a passphrase could open.
    pub fn is_enabled(&self) -> bool {
        self.active == SLOT_ENABLED
    }

    fn decode(b: &[u8]) -> Self {
        let mut salt = [0u8; SALT_BYTES];
        salt.copy_from_slice(&b[8..40]);
        Self {
            active: u32_be(b, 0),
            iterations: u32_be(b, 4),
            salt,
            key_material_offset: u32_be(b, 40),
            stripes: u32_be(b, 44),
        }
    }

    fn encode(&self, b: &mut [u8]) {
        b[0..4].copy_from_slice(&self.active.to_be_bytes());
        b[4..8].copy_from_slice(&self.iterations.to_be_bytes());
        b[8..40].copy_from_slice(&self.salt);
        b[40..44].copy_from_slice(&self.key_material_offset.to_be_bytes());
        b[44..48].copy_from_slice(&self.stripes.to_be_bytes());
    }
}

/// A decoded LUKS1 partition header.
#[derive(Debug, Clone)]
pub struct Header {
    pub cipher_name: String,
    pub cipher_mode: String,
    pub hash_spec: String,
    /// Start of the encrypted payload, in 512-byte sectors.
    pub payload_offset: u32,
    /// Master-key length in bytes.
    pub key_bytes: u32,
    pub mk_digest: [u8; DIGEST_BYTES],
    pub mk_digest_salt: [u8; SALT_BYTES],
    pub mk_digest_iter: u32,
    pub uuid: String,
    pub slots: [KeySlot; NUM_KEYS],
}

impl Header {
    /// Decode a phdr from at least [`PHDR_BYTES`] bytes.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < PHDR_BYTES {
            return Err(crate::Error::InvalidImage(format!(
                "luks1: header buffer is {} bytes, need ≥ {PHDR_BYTES}",
                buf.len()
            )));
        }
        if buf[0..6] != LUKS_MAGIC {
            return Err(crate::Error::InvalidImage(
                "luks1: bad magic (not a LUKS volume)".into(),
            ));
        }
        let version = u16::from_be_bytes([buf[6], buf[7]]);
        if version != 1 {
            return Err(crate::Error::InvalidImage(format!(
                "luks1: header says version {version}, not 1"
            )));
        }

        let mut mk_digest = [0u8; DIGEST_BYTES];
        mk_digest.copy_from_slice(&buf[112..132]);
        let mut mk_digest_salt = [0u8; SALT_BYTES];
        mk_digest_salt.copy_from_slice(&buf[132..164]);

        let mut slots = [KeySlot {
            active: SLOT_DISABLED,
            iterations: 0,
            salt: [0u8; SALT_BYTES],
            key_material_offset: 0,
            stripes: 0,
        }; NUM_KEYS];
        for (i, slot) in slots.iter_mut().enumerate() {
            *slot = KeySlot::decode(&buf[208 + i * 48..208 + (i + 1) * 48]);
        }

        let h = Self {
            cipher_name: cstr(&buf[8..40]),
            cipher_mode: cstr(&buf[40..72]),
            hash_spec: cstr(&buf[72..104]),
            payload_offset: u32_be(buf, 104),
            key_bytes: u32_be(buf, 108),
            mk_digest,
            mk_digest_salt,
            mk_digest_iter: u32_be(buf, 164),
            uuid: cstr(&buf[168..208]),
            slots,
        };
        h.validate()?;
        Ok(h)
    }

    fn validate(&self) -> Result<()> {
        // 4 KiB is already far past any real key length (the longest is
        // XTS-AES-256's 64 bytes); the bound exists so a hostile header
        // cannot make us reserve a huge buffer for AF material.
        if self.key_bytes == 0 || self.key_bytes > 4096 {
            return Err(crate::Error::InvalidImage(format!(
                "luks1: implausible key-bytes {}",
                self.key_bytes
            )));
        }
        if self.payload_offset == 0 {
            return Err(crate::Error::InvalidImage(
                "luks1: payload offset is 0 — it would overlap the header".into(),
            ));
        }
        if self.mk_digest_iter == 0 {
            return Err(crate::Error::InvalidImage(
                "luks1: master-key digest iteration count is 0".into(),
            ));
        }
        for (i, s) in self.slots.iter().enumerate() {
            if !s.is_enabled() {
                continue;
            }
            if s.iterations == 0 {
                return Err(crate::Error::InvalidImage(format!(
                    "luks1: keyslot {i} is enabled but has 0 PBKDF2 iterations"
                )));
            }
            if s.stripes == 0 {
                return Err(crate::Error::InvalidImage(format!(
                    "luks1: keyslot {i} is enabled but has 0 anti-forensic stripes"
                )));
            }
            // The material is buffered whole before anything validates
            // it, so an unbounded `stripes × key_bytes` is an
            // out-of-memory in one header field. Real slots use 4000
            // stripes of 64 bytes = 250 KiB.
            let material = s.stripes as u64 * self.key_bytes as u64;
            if material > super::v2::MAX_AF_MATERIAL_BYTES {
                return Err(crate::Error::InvalidImage(format!(
                    "luks1: keyslot {i} declares {} stripes of {} bytes = {material}, \
                     over the {} a keyslot may hold",
                    s.stripes,
                    self.key_bytes,
                    super::v2::MAX_AF_MATERIAL_BYTES
                )));
            }
        }
        Ok(())
    }

    /// The `cipher-name` and `cipher-mode` fields joined into the dm-crypt
    /// spec string the rest of the stack speaks.
    pub fn cipher_spec_string(&self) -> String {
        format!("{}-{}", self.cipher_name, self.cipher_mode)
    }

    /// Parse the header's cipher fields into a [`CipherSpec`].
    pub fn cipher_spec(&self) -> Result<CipherSpec> {
        CipherSpec::parse(&self.cipher_spec_string(), self.key_bytes as usize)
    }

    /// The header's hash, resolved.
    pub fn hash(&self) -> Result<HashAlgorithm> {
        hash::parse(&self.hash_spec)
    }

    /// Byte offset of the payload.
    pub fn payload_offset_bytes(&self) -> u64 {
        self.payload_offset as u64 * 512
    }

    /// Exact byte length of keyslot `i`'s anti-forensic material —
    /// `stripes × key_bytes`, before any sector rounding.
    pub fn slot_material_len(&self, i: usize) -> u64 {
        self.slots[i].stripes as u64 * self.key_bytes as u64
    }

    /// Byte offset and *sector-rounded* length of keyslot `i`'s material.
    ///
    /// The material is stored — and encrypted — in whole 512-byte sectors,
    /// so the read covers `round_up(stripes × key_bytes, 512)` bytes even
    /// though only the first `stripes × key_bytes` feed the AF merge. This
    /// is what cryptsetup's `AF_split_sectors` computes.
    pub fn slot_material_extent(&self, i: usize) -> (u64, u64) {
        (
            self.slots[i].key_material_offset as u64 * 512,
            self.slot_material_len(i).div_ceil(512) * 512,
        )
    }

    /// Check a master-key candidate against the stored digest. LUKS1 uses
    /// PBKDF2 over the key itself as the "did we get it right" test.
    pub fn verify_master_key(&self, mk: &[u8]) -> Result<bool> {
        let alg = self.hash()?;
        let mut got = [0u8; DIGEST_BYTES];
        hash::pbkdf2(alg, mk, &self.mk_digest_salt, self.mk_digest_iter, &mut got)?;
        Ok(constant_time_eq(&got, &self.mk_digest))
    }

    /// Derive the key that unwraps keyslot `i` from `passphrase`.
    pub fn slot_key(&self, i: usize, passphrase: &[u8]) -> Result<Vec<u8>> {
        let slot = &self.slots[i];
        let alg = self.hash()?;
        let mut out = vec![0u8; self.key_bytes as usize];
        hash::pbkdf2(alg, passphrase, &slot.salt, slot.iterations, &mut out)?;
        Ok(out)
    }

    /// Recover the master key from keyslot `i`'s raw (still encrypted) AF
    /// material and the passphrase. Returns `Ok(None)` when the material
    /// merges to a key the digest rejects — i.e. the wrong passphrase.
    ///
    /// `encrypted_material` is the slot's whole sector-rounded extent (see
    /// [`slot_material_extent`](Self::slot_material_extent)); it is
    /// decrypted in place.
    pub fn unlock_slot(
        &self,
        i: usize,
        passphrase: &[u8],
        encrypted_material: &mut [u8],
    ) -> Result<Option<Vec<u8>>> {
        let slot = &self.slots[i];
        let exact = self.slot_material_len(i) as usize;
        if encrypted_material.len() < exact {
            return Err(crate::Error::InvalidImage(format!(
                "luks1: keyslot {i} material is {} bytes, need {exact}",
                encrypted_material.len()
            )));
        }
        let derived = self.slot_key(i, passphrase)?;
        let cipher = SectorCipher::new(self.cipher_spec()?, &derived, 512)?;
        // Key material is addressed from sector 0 at the start of the slot,
        // not from the volume's sector 0.
        cipher.decrypt(0, encrypted_material)?;
        let mk = af::merge(
            self.hash()?,
            &encrypted_material[..exact],
            self.key_bytes as usize,
            slot.stripes,
        )?;
        if self.verify_master_key(&mk)? {
            Ok(Some(mk))
        } else {
            Ok(None)
        }
    }

    /// Encode back to a [`PHDR_BYTES`]-byte phdr.
    pub fn encode(&self) -> [u8; PHDR_BYTES] {
        let mut b = [0u8; PHDR_BYTES];
        b[0..6].copy_from_slice(&LUKS_MAGIC);
        b[6..8].copy_from_slice(&1u16.to_be_bytes());
        put_cstr(&mut b[8..40], &self.cipher_name);
        put_cstr(&mut b[40..72], &self.cipher_mode);
        put_cstr(&mut b[72..104], &self.hash_spec);
        b[104..108].copy_from_slice(&self.payload_offset.to_be_bytes());
        b[108..112].copy_from_slice(&self.key_bytes.to_be_bytes());
        b[112..132].copy_from_slice(&self.mk_digest);
        b[132..164].copy_from_slice(&self.mk_digest_salt);
        b[164..168].copy_from_slice(&self.mk_digest_iter.to_be_bytes());
        put_cstr(&mut b[168..208], &self.uuid);
        for (i, s) in self.slots.iter().enumerate() {
            s.encode(&mut b[208 + i * 48..208 + (i + 1) * 48]);
        }
        b
    }
}

/// Read a NUL-terminated (or field-filling) ASCII string out of a fixed
/// field, dropping everything from the first NUL.
fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|&c| c == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Write `s` into `field`, NUL-padded. Truncates silently if `s` is longer
/// than the field — every caller passes a value the format bounds anyway.
fn put_cstr(field: &mut [u8], s: &str) {
    field.fill(0);
    let n = s.len().min(field.len());
    field[..n].copy_from_slice(&s.as_bytes()[..n]);
}

fn u32_be(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(buf[off..off + 4].try_into().unwrap())
}

/// Compare two digests without an early exit. The digest is not itself
/// secret, but a timing-independent compare costs nothing here and keeps
/// the "wrong passphrase" path from leaking how far it matched.
pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            cipher_name: "aes".into(),
            cipher_mode: "xts-plain64".into(),
            hash_spec: "sha256".into(),
            payload_offset: 4096,
            key_bytes: 64,
            mk_digest: [1u8; DIGEST_BYTES],
            mk_digest_salt: [2u8; SALT_BYTES],
            mk_digest_iter: 5000,
            uuid: "c9f1a3e4-0000-4000-8000-000000000001".into(),
            slots: [KeySlot {
                active: SLOT_DISABLED,
                iterations: 0,
                salt: [0u8; SALT_BYTES],
                key_material_offset: 0,
                stripes: 0,
            }; NUM_KEYS],
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let mut h = sample();
        h.slots[0] = KeySlot {
            active: SLOT_ENABLED,
            iterations: 100_000,
            salt: [7u8; SALT_BYTES],
            key_material_offset: 8,
            stripes: 4000,
        };
        let bytes = h.encode();
        let d = Header::decode(&bytes).unwrap();
        assert_eq!(d.cipher_name, "aes");
        assert_eq!(d.cipher_mode, "xts-plain64");
        assert_eq!(d.hash_spec, "sha256");
        assert_eq!(d.key_bytes, 64);
        assert_eq!(d.payload_offset, 4096);
        assert_eq!(d.uuid, h.uuid);
        assert!(d.slots[0].is_enabled());
        assert_eq!(d.slots[0].stripes, 4000);
        assert!(!d.slots[1].is_enabled());
        assert_eq!(d.cipher_spec_string(), "aes-xts-plain64");
        assert_eq!(d.cipher_spec().unwrap().key_bytes, 64);
    }

    #[test]
    fn rejects_foreign_or_broken_headers() {
        let mut bytes = sample().encode();
        bytes[0] = b'X';
        assert!(Header::decode(&bytes).is_err());

        let mut bytes = sample().encode();
        bytes[6..8].copy_from_slice(&2u16.to_be_bytes()); // LUKS2
        assert!(Header::decode(&bytes).is_err());

        let mut bytes = sample().encode();
        bytes[108..112].copy_from_slice(&0u32.to_be_bytes()); // key_bytes = 0
        assert!(Header::decode(&bytes).is_err());

        let mut bytes = sample().encode();
        bytes[104..108].copy_from_slice(&0u32.to_be_bytes()); // payload at 0
        assert!(Header::decode(&bytes).is_err());
    }

    #[test]
    fn refuses_an_absurd_stripe_count() {
        let mut h = sample();
        h.slots[0] = KeySlot {
            active: SLOT_ENABLED,
            iterations: 1000,
            salt: [0u8; SALT_BYTES],
            key_material_offset: 8,
            stripes: u32::MAX,
        };
        let bytes = h.encode();
        assert!(matches!(
            Header::decode(&bytes),
            Err(crate::Error::InvalidImage(_))
        ));
    }

    #[test]
    fn truncated_buffer_is_an_error() {
        let bytes = sample().encode();
        assert!(Header::decode(&bytes[..200]).is_err());
    }

    /// Build a slot by hand — split a known master key, encrypt the
    /// stripes with the derived key — and check `unlock_slot` walks it
    /// back, and refuses a wrong passphrase.
    #[test]
    fn unlock_slot_round_trip() {
        let mut h = sample();
        h.key_bytes = 32;
        h.cipher_mode = "xts-plain64".into();
        // key_bytes 32 → XTS halves to AES-128. Fine.
        let mk = vec![0x33u8; 32];
        let alg = h.hash().unwrap();
        hash::pbkdf2(
            alg,
            &mk,
            &h.mk_digest_salt,
            h.mk_digest_iter,
            &mut h.mk_digest,
        )
        .unwrap();

        h.slots[0] = KeySlot {
            active: SLOT_ENABLED,
            iterations: 1000,
            salt: [9u8; SALT_BYTES],
            key_material_offset: 8,
            stripes: 16,
        };

        let random: Vec<u8> = (0..32 * 15).map(|i| (i as u8).wrapping_mul(13)).collect();
        let split = af::split(alg, &mk, 16, &random).unwrap();
        let derived = h.slot_key(0, b"open sesame").unwrap();
        let cipher = SectorCipher::new(h.cipher_spec().unwrap(), &derived, 512).unwrap();
        let mut material = split.clone();
        cipher.encrypt(0, &mut material).unwrap();

        let mut probe = material.clone();
        let got = h.unlock_slot(0, b"open sesame", &mut probe).unwrap();
        assert_eq!(got.as_deref(), Some(&mk[..]));

        let mut probe = material.clone();
        assert!(h.unlock_slot(0, b"wrong", &mut probe).unwrap().is_none());
    }

    #[test]
    fn constant_time_eq_behaves_like_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
