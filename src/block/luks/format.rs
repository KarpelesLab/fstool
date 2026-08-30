//! Formatting a fresh LUKS volume.
//!
//! [`format`] is the `cryptsetup luksFormat` of this crate: it draws a
//! random master key, wraps it under one passphrase in keyslot 0, writes
//! the header, and hands back the volume already unlocked so the caller
//! can go straight on to putting a partition table or filesystem inside
//! it.
//!
//! ## Layout it writes
//!
//! LUKS2 (the default):
//!
//! ```text
//!   0        primary header  (4096 binary + 12288 JSON)
//!   16384    secondary header (identical, magic "SKUL…")
//!   32768    keyslots area — eight slot-sized areas, slot 0 populated
//!   …        payload, starting at the next `data_alignment` boundary
//! ```
//!
//! LUKS1:
//!
//! ```text
//!   0        phdr (592 bytes)
//!   4096     keyslot 0 … 7 material areas, each 4096-aligned
//!   …        payload, starting at the next `data_alignment` boundary
//! ```
//!
//! Both reserve room for all eight keyslots even though only slot 0 is
//! written, so a later `cryptsetup luksAddKey` has somewhere to put a
//! second passphrase.
//!
//! ## Randomness
//!
//! The master key, every salt, and the anti-forensic stripes come from
//! `purecrypto`'s `OsRng` (`/dev/urandom` on Unix, `arc4random_buf` on
//! Apple platforms). The anti-forensic property of a keyslot rests
//! entirely on those stripes being unpredictable.
//!
//! ## What it does not do
//!
//! The unused keyslot areas are left as the caller's device presented
//! them rather than being overwritten with random bytes. `cryptsetup`
//! fills them so an observer cannot tell which slots are in use; for a
//! freshly created image there is nothing there to hide, but do not
//! expect that property when formatting over an existing device.

use purecrypto::rng::{OsRng, RngCore};

use crate::Result;

use super::af;
use super::crypt::{CipherSpec, SectorCipher};
use super::hash;
use super::v1;
use super::v2;
use super::{BlockDevice, LuksBackend, Version};

/// Which key-derivation function protects the keyslot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfChoice {
    /// PBKDF2 with the header's hash. The only choice LUKS1 has, and
    /// still legal in LUKS2.
    Pbkdf2 { iterations: u32 },
    /// Argon2id — LUKS2's default, and the one to prefer: its memory cost
    /// is what makes GPU cracking expensive.
    Argon2id {
        time: u32,
        memory_kib: u32,
        cpus: u32,
    },
    /// Argon2i — data-independent addressing. Accepted for interop.
    Argon2i {
        time: u32,
        memory_kib: u32,
        cpus: u32,
    },
}

/// Knobs for [`format`].
#[derive(Debug, Clone)]
pub struct FormatOpts {
    /// On-disk format to write.
    pub version: Version,
    /// dm-crypt cipher string for the payload, e.g. `"aes-xts-plain64"`.
    pub cipher: String,
    /// Master-key length in bytes. XTS counts both halves, so 64 is
    /// XTS-AES-256 and 32 is XTS-AES-128.
    pub key_bytes: usize,
    /// Hash for the keyslot KDF, the master-key digest and the
    /// anti-forensic splitter.
    pub hash: String,
    /// Payload sector size. LUKS2 only — LUKS1 is always 512.
    pub sector_size: u32,
    /// Passphrase → keyslot-key derivation.
    pub kdf: KdfChoice,
    /// Anti-forensic stripe count. 4000 is what every cryptsetup-made
    /// header uses; changing it is legal but pointless.
    pub stripes: u32,
    /// The payload starts at the next multiple of this. 1 MiB matches
    /// cryptsetup's default and keeps the payload aligned to any
    /// plausible erase block.
    pub data_alignment: u64,
    /// Volume UUID. A fresh v4 UUID is generated when this is `None`.
    pub uuid: Option<String>,
    /// LUKS2 label (ignored for LUKS1, which has no label field).
    pub label: String,
    /// Use this master key instead of drawing a random one. For
    /// reproducing a known volume; leave `None` in normal use.
    pub master_key: Option<Vec<u8>>,
}

impl Default for FormatOpts {
    fn default() -> Self {
        Self {
            version: Version::V2,
            cipher: "aes-xts-plain64".into(),
            key_bytes: 64,
            hash: "sha256".into(),
            sector_size: 512,
            // cryptsetup tunes this to a ~2 s target on the machine doing
            // the formatting; we cannot benchmark from here, so this is a
            // fixed, defensible middle: 512 MiB of memory and four passes.
            kdf: KdfChoice::Argon2id {
                time: 4,
                memory_kib: 512 * 1024,
                cpus: 4,
            },
            stripes: 4000,
            data_alignment: 1024 * 1024,
            uuid: None,
            label: String::new(),
            master_key: None,
        }
    }
}

impl FormatOpts {
    /// Defaults with a **deliberately negligible** KDF cost, for tests and
    /// fixtures.
    ///
    /// A volume formatted with these options is trivially brute-forceable.
    /// Never hand them to a user's data.
    pub fn fast_for_tests() -> Self {
        Self {
            kdf: KdfChoice::Pbkdf2 { iterations: 1000 },
            ..Self::default()
        }
    }

    /// Rounds `n` up to the payload alignment.
    fn align_data(&self, n: u64) -> u64 {
        let a = self.data_alignment.max(512);
        n.div_ceil(a) * a
    }

    fn validate(&self) -> Result<()> {
        // Parsing the cipher validates the key length against the
        // algorithm, so this catches `aes-xts-plain64` with 40 bytes.
        CipherSpec::parse(&self.cipher, self.key_bytes)?;
        hash::parse(&self.hash)?;
        if self.stripes == 0 {
            return Err(crate::Error::InvalidArgument(
                "luks: stripe count must be at least 1".into(),
            ));
        }
        if !self.data_alignment.is_multiple_of(512) || self.data_alignment == 0 {
            return Err(crate::Error::InvalidArgument(format!(
                "luks: data alignment {} must be a non-zero multiple of 512",
                self.data_alignment
            )));
        }
        match self.version {
            Version::V1 => {
                if !matches!(self.kdf, KdfChoice::Pbkdf2 { .. }) {
                    return Err(crate::Error::InvalidArgument(
                        "luks1: the format has no Argon2 keyslots — pick \
                         KdfChoice::Pbkdf2, or format LUKS2"
                            .into(),
                    ));
                }
                if self.sector_size != 512 {
                    return Err(crate::Error::InvalidArgument(
                        "luks1: the payload sector size is fixed at 512 bytes".into(),
                    ));
                }
            }
            Version::V2 => {
                if !(512..=4096).contains(&self.sector_size) || !self.sector_size.is_power_of_two()
                {
                    return Err(crate::Error::InvalidArgument(format!(
                        "luks2: sector size {} must be a power of two in 512..=4096",
                        self.sector_size
                    )));
                }
            }
        }
        Ok(())
    }

    /// Size of one keyslot's material area, rounded to the 4096-byte
    /// keyslot alignment.
    fn slot_area_bytes(&self) -> u64 {
        let exact = self.stripes as u64 * self.key_bytes as u64;
        exact.div_ceil(v1::KEYSLOT_ALIGN) * v1::KEYSLOT_ALIGN
    }
}

fn random(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    OsRng.fill_bytes(&mut v);
    v
}

/// Derive the keyslot key from `passphrase` under `kdf`.
fn derive_slot_key(
    kdf: &KdfChoice,
    hash_name: &str,
    salt: &[u8],
    passphrase: &[u8],
    out: &mut [u8],
) -> Result<()> {
    match *kdf {
        KdfChoice::Pbkdf2 { iterations } => {
            hash::pbkdf2(hash::parse(hash_name)?, passphrase, salt, iterations, out)
        }
        KdfChoice::Argon2id {
            time,
            memory_kib,
            cpus,
        }
        | KdfChoice::Argon2i {
            time,
            memory_kib,
            cpus,
        } => {
            let variant = if matches!(kdf, KdfChoice::Argon2id { .. }) {
                purecrypto::kdf::argon2::Argon2Type::Argon2id
            } else {
                purecrypto::kdf::argon2::Argon2Type::Argon2i
            };
            let params = purecrypto::kdf::argon2::Argon2Params {
                t_cost: time,
                m_cost_kib: memory_kib,
                parallelism: cpus,
                variant,
                version: 0x13,
            };
            purecrypto::kdf::argon2::argon2(&params, passphrase, salt, &[], &[], out)
                .map_err(|e| crate::Error::InvalidArgument(format!("luks: argon2: {e}")))
        }
    }
}

/// Build one keyslot's on-disk material: split the master key, encrypt the
/// stripes under the passphrase-derived key, and return the sector-rounded
/// buffer ready to write.
fn build_slot_material(
    opts: &FormatOpts,
    passphrase: &[u8],
    salt: &[u8],
    master_key: &[u8],
) -> Result<Vec<u8>> {
    let alg = hash::parse(&opts.hash)?;
    let stripe_bytes = master_key.len() * (opts.stripes as usize - 1);
    let split = af::split(alg, master_key, opts.stripes, &random(stripe_bytes))?;

    // The material occupies whole 512-byte sectors; pad the tail with
    // random rather than zeros so the used length is not visible.
    let rounded = split.len().div_ceil(512) * 512;
    let mut material = random(rounded);
    material[..split.len()].copy_from_slice(&split);

    let mut slot_key = vec![0u8; opts.key_bytes];
    derive_slot_key(&opts.kdf, &opts.hash, salt, passphrase, &mut slot_key)?;
    let spec = CipherSpec::parse(&opts.cipher, opts.key_bytes)?;
    SectorCipher::new(spec, &slot_key, 512)?.encrypt(0, &mut material)?;
    slot_key.fill(0);
    Ok(material)
}

/// Format `dev` as a LUKS volume protected by `passphrase`, and return it
/// unlocked.
///
/// The whole device is claimed: the header goes at offset 0 and the
/// payload runs from the first aligned offset past the keyslots to the end
/// of the device. Anything already on `dev` is overwritten.
pub fn format<B: BlockDevice>(
    dev: B,
    passphrase: &str,
    opts: &FormatOpts,
) -> Result<LuksBackend<B>> {
    opts.validate()?;
    let master_key = match &opts.master_key {
        Some(k) if k.len() == opts.key_bytes => k.clone(),
        Some(k) => {
            return Err(crate::Error::InvalidArgument(format!(
                "luks: supplied master key is {} bytes, key_bytes says {}",
                k.len(),
                opts.key_bytes
            )));
        }
        None => random(opts.key_bytes),
    };
    match opts.version {
        Version::V1 => format_v1(dev, passphrase, opts, &master_key),
        Version::V2 => format_v2(dev, passphrase, opts, &master_key),
    }
}

/// A LUKS1 header region built in memory: the phdr, the eight keyslot
/// areas, and the master key that unlocks it.
///
/// [`format_v1`] writes this at offset 0 of a device. qcow2's
/// `crypt_method = 2` embeds the very same bytes somewhere inside the
/// image file instead — see [`crate::block::qcow2::crypto`].
pub struct Luks1Image {
    /// The whole header region: `4096 + 8 × slot_area` bytes.
    pub bytes: Vec<u8>,
    /// The volume's master key.
    pub master_key: Vec<u8>,
    /// Value written into the phdr's `payload-offset` field, in sectors.
    pub payload_offset_sectors: u32,
}

/// Build a LUKS1 header region protected by `passphrase`.
///
/// `payload_offset` is the byte offset the phdr should advertise for the
/// payload. A standalone volume passes where its payload really starts;
/// an embedded header (qcow2) passes the region's own length, since the
/// payload is not laid out after the header at all.
pub fn build_luks1(
    passphrase: &str,
    opts: &FormatOpts,
    payload_offset: u64,
    master_key: &[u8],
) -> Result<Luks1Image> {
    let slot_area = opts.slot_area_bytes();

    // Split "aes-xts-plain64" back into the two fields LUKS1 stores.
    let (cipher_name, cipher_mode) = opts.cipher.split_once('-').ok_or_else(|| {
        crate::Error::InvalidArgument(format!(
            "luks1: cipher spec `{}` has no mode part",
            opts.cipher
        ))
    })?;

    let KdfChoice::Pbkdf2 { iterations } = opts.kdf else {
        return Err(crate::Error::InvalidArgument(
            "luks1: the format has no Argon2 keyslots — pick KdfChoice::Pbkdf2, \
             or format LUKS2"
                .into(),
        ));
    };
    // cryptsetup spends a fraction of the keyslot budget on the master-key
    // digest; a tenth, floored at the format's 1000-round minimum.
    let digest_iter = (iterations / 10).max(1000);

    let alg = hash::parse(&opts.hash)?;
    let mut mk_digest_salt = [0u8; v1::SALT_BYTES];
    mk_digest_salt.copy_from_slice(&random(v1::SALT_BYTES));
    let mut mk_digest = [0u8; v1::DIGEST_BYTES];
    hash::pbkdf2(
        alg,
        master_key,
        &mk_digest_salt,
        digest_iter,
        &mut mk_digest,
    )?;

    let mut slot_salt = [0u8; v1::SALT_BYTES];
    slot_salt.copy_from_slice(&random(v1::SALT_BYTES));

    let mut slots = [v1::KeySlot {
        active: v1::SLOT_DISABLED,
        iterations: 0,
        salt: [0u8; v1::SALT_BYTES],
        key_material_offset: 0,
        stripes: 0,
    }; v1::NUM_KEYS];
    for (i, slot) in slots.iter_mut().enumerate() {
        // Every slot gets its reserved area recorded, so `luksAddKey` has
        // somewhere to write; only slot 0 is marked active.
        slot.key_material_offset = ((v1::KEYSLOT_ALIGN + slot_area * i as u64) / 512) as u32;
        slot.stripes = opts.stripes;
    }
    slots[0].active = v1::SLOT_ENABLED;
    slots[0].iterations = iterations;
    slots[0].salt = slot_salt;

    let payload_offset_sectors = (payload_offset / 512) as u32;
    let header = v1::Header {
        cipher_name: cipher_name.to_string(),
        cipher_mode: cipher_mode.to_string(),
        hash_spec: opts.hash.clone(),
        payload_offset: payload_offset_sectors,
        key_bytes: opts.key_bytes as u32,
        mk_digest,
        mk_digest_salt,
        mk_digest_iter: digest_iter,
        uuid: opts
            .uuid
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        slots,
    };

    let material = build_slot_material(opts, passphrase.as_bytes(), &slot_salt, master_key)?;

    let mut bytes = vec![0u8; (v1::KEYSLOT_ALIGN + slot_area * v1::NUM_KEYS as u64) as usize];
    bytes[..v1::PHDR_BYTES].copy_from_slice(&header.encode());
    let slot0 = v1::KEYSLOT_ALIGN as usize;
    bytes[slot0..slot0 + material.len()].copy_from_slice(&material);
    Ok(Luks1Image {
        bytes,
        master_key: master_key.to_vec(),
        payload_offset_sectors,
    })
}

fn format_v1<B: BlockDevice>(
    mut dev: B,
    passphrase: &str,
    opts: &FormatOpts,
    master_key: &[u8],
) -> Result<LuksBackend<B>> {
    let slot_area = opts.slot_area_bytes();
    let keyslots_end = v1::KEYSLOT_ALIGN + slot_area * v1::NUM_KEYS as u64;
    let payload_offset = opts.align_data(keyslots_end);
    if payload_offset >= dev.total_size() {
        return Err(crate::Error::InvalidArgument(format!(
            "luks1: the header and eight keyslots need {payload_offset} bytes, \
             but the device is only {} — use a bigger device, fewer stripes, \
             or a smaller data alignment",
            dev.total_size()
        )));
    }

    let image = build_luks1(passphrase, opts, payload_offset, master_key)?;
    // Writing the whole region (not just the phdr and slot 0) also clears
    // any stale keyslot material left by whatever was on the device.
    dev.write_at(0, &image.bytes)?;
    dev.sync()?;

    LuksBackend::open(dev, passphrase)
}

fn format_v2<B: BlockDevice>(
    mut dev: B,
    passphrase: &str,
    opts: &FormatOpts,
    master_key: &[u8],
) -> Result<LuksBackend<B>> {
    let hdr_size = v2::DEFAULT_HDR_BYTES;
    let keyslots_offset = 2 * hdr_size;
    let slot_area = opts.slot_area_bytes();
    let keyslots_end = keyslots_offset + slot_area * v1::NUM_KEYS as u64;
    let payload_offset = opts.align_data(keyslots_end);
    if payload_offset >= dev.total_size() {
        return Err(crate::Error::InvalidArgument(format!(
            "luks2: the headers and eight keyslots need {payload_offset} bytes, \
             but the device is only {} — use a bigger device, fewer stripes, \
             or a smaller data alignment",
            dev.total_size()
        )));
    }
    let payload_size =
        (dev.total_size() - payload_offset) / opts.sector_size as u64 * opts.sector_size as u64;
    if payload_size == 0 {
        return Err(crate::Error::InvalidArgument(
            "luks2: no room left for a payload after the header".into(),
        ));
    }

    let alg = hash::parse(&opts.hash)?;
    let slot_salt = random(v1::SALT_BYTES);
    let digest_salt = random(v1::SALT_BYTES);
    // LUKS2's digest is a full-length hash, not LUKS1's truncated 20 bytes.
    let digest_iterations = 1000u32;
    let digest = v2::Digest::compute(
        alg,
        master_key,
        &digest_salt,
        digest_iterations,
        alg.output_len(),
    )?;

    let kdf = match opts.kdf {
        KdfChoice::Pbkdf2 { iterations } => v2::Kdf::Pbkdf2 {
            salt: crate::base64::encode(&slot_salt),
            hash: opts.hash.clone(),
            iterations,
        },
        KdfChoice::Argon2id {
            time,
            memory_kib,
            cpus,
        } => v2::Kdf::Argon2id {
            salt: crate::base64::encode(&slot_salt),
            time,
            memory: memory_kib,
            cpus,
        },
        KdfChoice::Argon2i {
            time,
            memory_kib,
            cpus,
        } => v2::Kdf::Argon2i {
            salt: crate::base64::encode(&slot_salt),
            time,
            memory: memory_kib,
            cpus,
        },
    };

    let mut meta = v2::Metadata {
        keyslots: Default::default(),
        tokens: Default::default(),
        segments: Default::default(),
        digests: Default::default(),
        config: v2::Config {
            json_size: hdr_size - v2::BIN_HDR_BYTES as u64,
            keyslots_size: payload_offset - keyslots_offset,
            flags: Vec::new(),
            requirements: None,
        },
    };
    meta.keyslots.insert(
        "0".into(),
        v2::KeySlot {
            kind: "luks2".into(),
            key_size: opts.key_bytes,
            af: v2::Af {
                kind: "luks1".into(),
                stripes: opts.stripes,
                hash: opts.hash.clone(),
            },
            area: v2::Area {
                kind: "raw".into(),
                offset: keyslots_offset,
                size: slot_area,
                encryption: opts.cipher.clone(),
                key_size: opts.key_bytes,
            },
            kdf,
            priority: None,
        },
    );
    meta.segments.insert(
        "0".into(),
        v2::Segment {
            kind: "crypt".into(),
            offset: payload_offset,
            size: "dynamic".into(),
            iv_tweak: 0,
            encryption: opts.cipher.clone(),
            sector_size: opts.sector_size,
            integrity: None,
            flags: Vec::new(),
        },
    );
    meta.digests.insert(
        "0".into(),
        v2::Digest {
            kind: "pbkdf2".into(),
            keyslots: vec!["0".into()],
            segments: vec!["0".into()],
            hash: opts.hash.clone(),
            iterations: digest_iterations,
            salt: crate::base64::encode(&digest_salt),
            digest,
        },
    );

    let json = meta.to_json()?;
    let uuid = opts
        .uuid
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Both copies carry the same seqid and the same JSON; they differ only
    // in magic, offset and their per-copy salt.
    for (i, offset) in [0u64, hdr_size].into_iter().enumerate() {
        let mut salt = [0u8; 64];
        salt.copy_from_slice(&random(64));
        let bin = v2::BinHeader {
            secondary: i == 1,
            hdr_size,
            seqid: 1,
            label: opts.label.clone(),
            checksum_alg: "sha256".into(),
            salt,
            uuid: uuid.clone(),
            subsystem: String::new(),
            hdr_offset: offset,
            csum: [0u8; 64],
        };
        let region = v2::seal(&bin, &json)?;
        dev.write_at(offset, &region)?;
    }

    let material = build_slot_material(opts, passphrase.as_bytes(), &slot_salt, master_key)?;
    dev.write_at(keyslots_offset, &material)?;
    dev.sync()?;

    LuksBackend::open(dev, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;

    #[test]
    fn refuses_argon2_for_luks1() {
        let opts = FormatOpts {
            version: Version::V1,
            ..FormatOpts::default()
        };
        let err = format(MemoryBackend::new(8 << 20), "pw", &opts).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidArgument(_)), "{err}");
    }

    #[test]
    fn refuses_a_device_too_small_for_the_header() {
        let opts = FormatOpts::fast_for_tests();
        let err = format(MemoryBackend::new(256 * 1024), "pw", &opts).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidArgument(_)), "{err}");
    }

    #[test]
    fn refuses_a_key_length_the_cipher_rejects() {
        let opts = FormatOpts {
            key_bytes: 40, // halves to 20, no AES key length
            ..FormatOpts::fast_for_tests()
        };
        assert!(format(MemoryBackend::new(8 << 20), "pw", &opts).is_err());
    }

    #[test]
    fn refuses_a_mis_sized_supplied_master_key() {
        let opts = FormatOpts {
            master_key: Some(vec![0u8; 16]),
            ..FormatOpts::fast_for_tests()
        };
        let err = format(MemoryBackend::new(8 << 20), "pw", &opts).unwrap_err();
        assert!(matches!(err, crate::Error::InvalidArgument(_)), "{err}");
    }

    #[test]
    fn honours_a_supplied_master_key() {
        let mk = vec![0x42u8; 64];
        let opts = FormatOpts {
            master_key: Some(mk.clone()),
            ..FormatOpts::fast_for_tests()
        };
        let vol = format(MemoryBackend::new(8 << 20), "pw", &opts).unwrap();
        assert_eq!(vol.master_key().as_bytes(), &mk[..]);
    }

    #[test]
    fn payload_lands_on_the_requested_alignment() {
        for alignment in [4096u64, 64 * 1024, 1024 * 1024] {
            let opts = FormatOpts {
                data_alignment: alignment,
                ..FormatOpts::fast_for_tests()
            };
            let vol = format(MemoryBackend::new(16 << 20), "pw", &opts).unwrap();
            assert_eq!(
                vol.payload_offset() % alignment,
                0,
                "alignment {alignment} not honoured"
            );
        }
    }

    /// Both header copies must be written, and either alone must be enough
    /// to open the volume.
    #[test]
    fn luks2_writes_a_usable_secondary_header() {
        let opts = FormatOpts::fast_for_tests();
        let vol = format(MemoryBackend::new(8 << 20), "pw", &opts).unwrap();
        let mut dev = vol.into_inner();

        // Corrupt the primary copy's JSON; the spare must carry the open.
        let mut byte = [0u8; 1];
        dev.read_at(5000, &mut byte).unwrap();
        byte[0] ^= 0xff;
        dev.write_at(5000, &byte).unwrap();

        let vol = LuksBackend::open(dev, "pw").unwrap();
        assert_eq!(vol.version(), Version::V2);
    }

    #[test]
    fn reports_the_cipher_it_wrote() {
        let opts = FormatOpts::fast_for_tests();
        let vol = format(MemoryBackend::new(8 << 20), "pw", &opts).unwrap();
        assert_eq!(
            vol.header().cipher_spec_string().unwrap(),
            "aes-xts-plain64"
        );
        assert!(!vol.header().uuid().is_empty());
    }
}
