//! LUKS2 — the JSON-metadata format.
//!
//! LUKS2 keeps a small fixed binary header for self-identification and
//! integrity, and puts everything else in a JSON document that follows it:
//!
//! ```text
//!   0        primary binary header   (4096 bytes)
//!   4096     primary JSON area       (hdr_size − 4096 bytes)
//!   hdr_size secondary binary header (a byte-for-byte spare, magic "SKUL…")
//!   …        secondary JSON area
//!   32768    keyslots area           (anti-forensic key material)
//!   …        the segment: encrypted payload
//! ```
//!
//! Both header copies carry a `seqid`; the one with the higher `seqid`
//! whose checksum verifies is authoritative. That is how an interrupted
//! `cryptsetup luksAddKey` cannot leave a volume unopenable.
//!
//! ## Binary header layout (big-endian)
//!
//! ```text
//!     0   6  magic          "LUKS\xba\xbe" primary / "SKUL\xba\xbe" secondary
//!     6   2  version        2
//!     8   8  hdr_size       binary header + JSON area, in bytes
//!    16   8  seqid
//!    24  48  label
//!    72  32  checksum_alg   "sha256"
//!   104  64  salt
//!   168  40  uuid
//!   208  48  subsystem
//!   256   8  hdr_offset     this copy's own offset, in bytes
//!   264 184  padding
//!   448  64  csum           digest over hdr_size bytes with csum zeroed
//!   512 3584 padding to 4096
//! ```
//!
//! ## JSON metadata
//!
//! Four objects matter here. `keyslots` map an id to the anti-forensic
//! material for one passphrase, plus the KDF (Argon2id by default,
//! PBKDF2 for `--pbkdf pbkdf2` volumes) that turns the passphrase into
//! the key unwrapping it. `segments` describe the encrypted payload —
//! where it starts, which cipher, what sector size, and the `iv_tweak`
//! the IV generator counts from. `digests` bind a master key to the
//! keyslots and segments it opens, and are the check that says whether a
//! passphrase was right. `config` records the sizes of the JSON and
//! keyslots areas.
//!
//! 64-bit quantities are JSON *strings* throughout ("offset": "32768") —
//! JSON numbers are doubles and would lose precision past 2⁵³ — so the
//! `u64_str` helpers below do that conversion.
//!
//! ## Not implemented
//!
//! `--integrity` volumes (a `dm-integrity` layer under the crypt layer)
//! and volumes with unmet `requirements` in `config` are rejected on
//! open: both change the meaning of the payload bytes, and silently
//! ignoring either would hand back plausible-looking garbage.

use std::collections::BTreeMap;

use purecrypto::hash::HashAlgorithm;
use serde::{Deserialize, Serialize};

use crate::Result;
use crate::base64;

use super::af;
use super::crypt::{CipherSpec, SectorCipher};
use super::hash;

/// Magic of the primary header copy — the same six bytes LUKS1 uses.
pub const MAGIC_1ST: [u8; 6] = [b'L', b'U', b'K', b'S', 0xba, 0xbe];
/// Magic of the secondary (spare) header copy.
pub const MAGIC_2ND: [u8; 6] = [b'S', b'K', b'U', b'L', 0xba, 0xbe];

/// Fixed size of one binary header copy.
pub const BIN_HDR_BYTES: usize = 4096;

/// Default total metadata size per copy (binary header + JSON area).
/// cryptsetup's default; `hdr_size` records the actual value.
pub const DEFAULT_HDR_BYTES: u64 = 16384;

/// Default start of the keyslots area — right after both header copies at
/// the default `hdr_size`.
pub const DEFAULT_KEYSLOTS_OFFSET: u64 = 2 * DEFAULT_HDR_BYTES;

/// Upper bound on a keyslot's anti-forensic material, in bytes.
///
/// `stripes × key_size` both come out of the JSON, and the material is
/// buffered whole before anything validates it — so without a cap a
/// hostile header is a one-line out-of-memory. 64 MiB is ~250× what a
/// real keyslot uses (4000 stripes × 64 bytes = 250 KiB).
pub const MAX_AF_MATERIAL_BYTES: u64 = 64 * 1024 * 1024;

/// Upper bound on the Argon2 memory cost we will honour, in KiB (4 GiB).
///
/// `memory` comes straight out of an attacker-supplied header and
/// Argon2 allocates exactly that much, so an unbounded value is an
/// out-of-memory DoS. 4 GiB is the LUKS2 format's own ceiling, so no
/// legitimate volume is refused by this.
pub const MAX_ARGON2_MEMORY_KIB: u32 = 4 * 1024 * 1024;

/// The decoded fixed binary header.
#[derive(Debug, Clone)]
pub struct BinHeader {
    /// True for the `"SKUL"` spare copy.
    pub secondary: bool,
    /// Binary header + JSON area size, in bytes.
    pub hdr_size: u64,
    /// Update counter; the newest valid copy wins.
    pub seqid: u64,
    pub label: String,
    pub checksum_alg: String,
    pub salt: [u8; 64],
    pub uuid: String,
    pub subsystem: String,
    /// Byte offset this copy claims to live at.
    pub hdr_offset: u64,
    /// Stored checksum, `checksum_alg`-length bytes of the 64-byte field.
    pub csum: [u8; 64],
}

impl BinHeader {
    /// Decode the 4096-byte binary header. Does **not** verify the
    /// checksum — that needs the JSON area too; see [`verify_checksum`].
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < BIN_HDR_BYTES {
            return Err(crate::Error::InvalidImage(format!(
                "luks2: header buffer is {} bytes, need ≥ {BIN_HDR_BYTES}",
                buf.len()
            )));
        }
        let secondary = if buf[0..6] == MAGIC_1ST {
            false
        } else if buf[0..6] == MAGIC_2ND {
            true
        } else {
            return Err(crate::Error::InvalidImage(
                "luks2: bad magic (not a LUKS2 header)".into(),
            ));
        };
        let version = u16::from_be_bytes([buf[6], buf[7]]);
        if version != 2 {
            return Err(crate::Error::InvalidImage(format!(
                "luks2: header says version {version}, not 2"
            )));
        }
        let hdr_size = u64_be(buf, 8);
        if hdr_size <= BIN_HDR_BYTES as u64 || hdr_size > 64 * 1024 * 1024 {
            return Err(crate::Error::InvalidImage(format!(
                "luks2: implausible hdr_size {hdr_size}"
            )));
        }
        let mut salt = [0u8; 64];
        salt.copy_from_slice(&buf[104..168]);
        let mut csum = [0u8; 64];
        csum.copy_from_slice(&buf[448..512]);
        Ok(Self {
            secondary,
            hdr_size,
            seqid: u64_be(buf, 16),
            label: cstr(&buf[24..72]),
            checksum_alg: cstr(&buf[72..104]),
            salt,
            uuid: cstr(&buf[168..208]),
            subsystem: cstr(&buf[208..256]),
            hdr_offset: u64_be(buf, 256),
            csum,
        })
    }

    /// Encode back to 4096 bytes, leaving `csum` as stored. Use
    /// [`seal`] to compute and stamp the checksum instead.
    pub fn encode(&self) -> [u8; BIN_HDR_BYTES] {
        let mut b = [0u8; BIN_HDR_BYTES];
        b[0..6].copy_from_slice(if self.secondary {
            &MAGIC_2ND
        } else {
            &MAGIC_1ST
        });
        b[6..8].copy_from_slice(&2u16.to_be_bytes());
        b[8..16].copy_from_slice(&self.hdr_size.to_be_bytes());
        b[16..24].copy_from_slice(&self.seqid.to_be_bytes());
        put_cstr(&mut b[24..72], &self.label);
        put_cstr(&mut b[72..104], &self.checksum_alg);
        b[104..168].copy_from_slice(&self.salt);
        put_cstr(&mut b[168..208], &self.uuid);
        put_cstr(&mut b[208..256], &self.subsystem);
        b[256..264].copy_from_slice(&self.hdr_offset.to_be_bytes());
        b[448..512].copy_from_slice(&self.csum);
        b
    }
}

/// Verify a header copy's checksum. `region` is the whole `hdr_size`-byte
/// span: the 4096-byte binary header followed by its JSON area.
pub fn verify_checksum(hdr: &BinHeader, region: &[u8]) -> Result<bool> {
    let alg = hash::parse(&hdr.checksum_alg)?;
    let want = compute_checksum(alg, region);
    let dlen = alg.output_len().min(64);
    Ok(super::v1::constant_time_eq(
        &want[..dlen],
        &hdr.csum[..dlen],
    ))
}

/// Digest a `hdr_size`-byte header region with the `csum` field zeroed —
/// the value that belongs in `csum`.
fn compute_checksum(alg: HashAlgorithm, region: &[u8]) -> Vec<u8> {
    let mut scratch = region.to_vec();
    scratch[448..512].fill(0);
    hash::digest(alg, &scratch)
}

/// Assemble one complete header copy: binary header, JSON area, and a
/// freshly computed checksum. Returns exactly `hdr.hdr_size` bytes.
pub fn seal(hdr: &BinHeader, json: &str) -> Result<Vec<u8>> {
    let json_area = hdr.hdr_size as usize - BIN_HDR_BYTES;
    if json.len() >= json_area {
        return Err(crate::Error::InvalidArgument(format!(
            "luks2: JSON metadata is {} bytes but the area holds {} \
             (it must also leave room for the NUL terminator)",
            json.len(),
            json_area
        )));
    }
    let alg = hash::parse(&hdr.checksum_alg)?;
    let mut region = vec![0u8; hdr.hdr_size as usize];
    region[..BIN_HDR_BYTES].copy_from_slice(&hdr.encode());
    region[BIN_HDR_BYTES..BIN_HDR_BYTES + json.len()].copy_from_slice(json.as_bytes());
    let csum = compute_checksum(alg, &region);
    region[448..448 + csum.len().min(64)].copy_from_slice(&csum[..csum.len().min(64)]);
    Ok(region)
}

/// Extract the JSON text from a header region, stopping at the first NUL.
pub fn json_text(region: &[u8]) -> Result<&str> {
    if region.len() <= BIN_HDR_BYTES {
        return Err(crate::Error::InvalidImage(
            "luks2: header region has no JSON area".into(),
        ));
    }
    let area = &region[BIN_HDR_BYTES..];
    let end = area.iter().position(|&c| c == 0).unwrap_or(area.len());
    std::str::from_utf8(&area[..end])
        .map_err(|e| crate::Error::InvalidImage(format!("luks2: JSON area is not UTF-8: {e}")))
}

// ---------------------------------------------------------------- metadata

/// The LUKS2 JSON metadata document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(default)]
    pub keyslots: BTreeMap<String, KeySlot>,
    #[serde(default)]
    pub tokens: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub segments: BTreeMap<String, Segment>,
    #[serde(default)]
    pub digests: BTreeMap<String, Digest>,
    pub config: Config,
}

/// One keyslot: the anti-forensic material for a single passphrase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlot {
    /// `"luks2"` for a passphrase slot. `"reencrypt"` marks the scratch
    /// slot an interrupted online re-encryption leaves behind.
    #[serde(rename = "type")]
    pub kind: String,
    /// Master-key length this slot stores, in bytes.
    pub key_size: usize,
    pub af: Af,
    pub area: Area,
    pub kdf: Kdf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i64>,
}

/// Anti-forensic splitter parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Af {
    #[serde(rename = "type")]
    pub kind: String,
    pub stripes: u32,
    pub hash: String,
}

/// Where a keyslot's material lives and how it is encrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Area {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(with = "u64_str")]
    pub offset: u64,
    #[serde(with = "u64_str")]
    pub size: u64,
    pub encryption: String,
    pub key_size: usize,
}

/// The passphrase → keyslot-key derivation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Kdf {
    #[serde(rename = "pbkdf2")]
    Pbkdf2 {
        salt: String,
        hash: String,
        iterations: u32,
    },
    #[serde(rename = "argon2i")]
    Argon2i {
        salt: String,
        time: u32,
        /// Memory cost in KiB.
        memory: u32,
        cpus: u32,
    },
    #[serde(rename = "argon2id")]
    Argon2id {
        salt: String,
        time: u32,
        /// Memory cost in KiB.
        memory: u32,
        cpus: u32,
    },
}

/// A stretch of the device and the cipher covering it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(with = "u64_str")]
    pub offset: u64,
    /// `"dynamic"` (grow to the end of the device) or a byte count.
    pub size: String,
    #[serde(with = "u64_str")]
    pub iv_tweak: u64,
    pub encryption: String,
    pub sector_size: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
}

/// Binds a master key to the keyslots that store it and the segments it
/// decrypts. Also the "was the passphrase right?" check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digest {
    #[serde(rename = "type")]
    pub kind: String,
    pub keyslots: Vec<String>,
    pub segments: Vec<String>,
    pub hash: String,
    pub iterations: u32,
    pub salt: String,
    pub digest: String,
}

/// Area sizes and volume-wide flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(with = "u64_str")]
    pub json_size: u64,
    #[serde(with = "u64_str")]
    pub keyslots_size: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    /// Features a reader must understand before touching the volume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements: Option<serde_json::Value>,
}

/// LUKS2 writes every 64-bit quantity as a decimal *string*, because JSON
/// numbers are IEEE doubles and would lose precision past 2⁵³.
mod u64_str {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<u64>()
            .map_err(|e| D::Error::custom(format!("expected a decimal u64 string, got {s:?}: {e}")))
    }
}

impl Metadata {
    /// Parse the JSON metadata document.
    pub fn parse(json: &str) -> Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| crate::Error::InvalidImage(format!("luks2: bad JSON metadata: {e}")))
    }

    /// Serialise back to compact JSON — the form cryptsetup writes.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| {
            crate::Error::InvalidImage(format!("luks2: cannot serialise metadata: {e}"))
        })
    }

    /// Reject volumes whose layout we would misread. Called on open.
    pub fn check_supported(&self) -> Result<()> {
        if let Some(req) = &self.requirements_list()
            && !req.is_empty()
        {
            return Err(crate::Error::Unsupported(format!(
                "luks2: volume declares unmet requirements {req:?} \
                 (online re-encryption in progress, or a newer feature)"
            )));
        }
        Ok(())
    }

    fn requirements_list(&self) -> Option<Vec<String>> {
        let mandatory = self.config.requirements.as_ref()?.get("mandatory")?;
        Some(
            mandatory
                .as_array()?
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect(),
        )
    }

    /// The data segment — the one holding the payload. LUKS2 permits
    /// several (online re-encryption uses two), but a volume at rest has
    /// exactly one `crypt` segment that is not a re-encryption scratch
    /// area.
    pub fn data_segment(&self) -> Result<(&str, &Segment)> {
        let mut found: Option<(&str, &Segment)> = None;
        for (id, seg) in &self.segments {
            if seg.kind != "crypt" {
                continue;
            }
            if found.is_some() {
                return Err(crate::Error::Unsupported(
                    "luks2: volume has several crypt segments — an online \
                     re-encryption is in progress; finish it with cryptsetup first"
                        .into(),
                ));
            }
            found = Some((id.as_str(), seg));
        }
        found.ok_or_else(|| {
            crate::Error::InvalidImage("luks2: metadata has no `crypt` segment".into())
        })
    }
}

impl Segment {
    /// Cipher spec for this segment, given the master-key length.
    pub fn cipher_spec(&self, key_bytes: usize) -> Result<CipherSpec> {
        if let Some(integ) = &self.integrity {
            return Err(crate::Error::Unsupported(format!(
                "luks2: segment uses dm-integrity ({integ}), which fstool does not implement"
            )));
        }
        self.validate()?;
        CipherSpec::parse(&self.encryption, key_bytes)
    }

    /// Validate the fields a caller divides by or allocates from.
    pub fn validate(&self) -> Result<()> {
        if !(512..=1024 * 1024).contains(&self.sector_size) || !self.sector_size.is_power_of_two() {
            return Err(crate::Error::InvalidImage(format!(
                "luks2: segment sector_size {} is not a power of two in 512..=1048576",
                self.sector_size
            )));
        }
        Ok(())
    }

    /// Payload length in bytes, or `None` for `"dynamic"` (runs to the end
    /// of the device).
    pub fn size_bytes(&self) -> Result<Option<u64>> {
        if self.size == "dynamic" {
            return Ok(None);
        }
        self.size.parse::<u64>().map(Some).map_err(|e| {
            crate::Error::InvalidImage(format!(
                "luks2: segment size {:?} is neither \"dynamic\" nor a decimal u64: {e}",
                self.size
            ))
        })
    }
}

impl Kdf {
    /// Derive `out.len()` bytes from `passphrase` with this KDF.
    pub fn derive(&self, passphrase: &[u8], out: &mut [u8]) -> Result<()> {
        match self {
            Kdf::Pbkdf2 {
                salt,
                hash: h,
                iterations,
            } => {
                let salt = base64::decode(salt)?;
                hash::pbkdf2(hash::parse(h)?, passphrase, &salt, *iterations, out)
            }
            Kdf::Argon2i {
                salt,
                time,
                memory,
                cpus,
            }
            | Kdf::Argon2id {
                salt,
                time,
                memory,
                cpus,
            } => {
                let variant = if matches!(self, Kdf::Argon2i { .. }) {
                    purecrypto::kdf::argon2::Argon2Type::Argon2i
                } else {
                    purecrypto::kdf::argon2::Argon2Type::Argon2id
                };
                if *memory > MAX_ARGON2_MEMORY_KIB {
                    return Err(crate::Error::InvalidImage(format!(
                        "luks2: keyslot asks for {memory} KiB of Argon2 memory, \
                         over the {MAX_ARGON2_MEMORY_KIB} KiB cap"
                    )));
                }
                let salt = base64::decode(salt)?;
                let params = purecrypto::kdf::argon2::Argon2Params {
                    t_cost: *time,
                    m_cost_kib: *memory,
                    parallelism: *cpus,
                    variant,
                    version: 0x13,
                };
                purecrypto::kdf::argon2::argon2(&params, passphrase, &salt, &[], &[], out).map_err(
                    |e| {
                        crate::Error::InvalidImage(format!(
                            "luks2: argon2 rejected the header: {e}"
                        ))
                    },
                )
            }
        }
    }
}

impl KeySlot {
    /// Byte offset and length of this slot's anti-forensic material.
    ///
    /// The material is `stripes × key_size` bytes rounded up to whole
    /// 512-byte sectors — the encryption covers the rounded span, the
    /// merge consumes the exact prefix.
    pub fn material_extent(&self) -> Result<(u64, u64)> {
        let exact = (self.key_size as u64)
            .checked_mul(self.af.stripes as u64)
            .ok_or_else(|| crate::Error::InvalidImage("luks2: AF material overflows".into()))?;
        if exact == 0 || exact > MAX_AF_MATERIAL_BYTES {
            return Err(crate::Error::InvalidImage(format!(
                "luks2: keyslot declares {} stripes of {} bytes = {exact}, outside                  the 1..={MAX_AF_MATERIAL_BYTES} bytes a keyslot may hold",
                self.af.stripes, self.key_size
            )));
        }
        let rounded = exact.div_ceil(512) * 512;
        if rounded > self.area.size {
            return Err(crate::Error::InvalidImage(format!(
                "luks2: keyslot needs {rounded} bytes of AF material but its area is {}",
                self.area.size
            )));
        }
        Ok((self.area.offset, rounded))
    }

    /// Recover the master key from this slot's raw (still encrypted)
    /// material. `encrypted_material` is the slot's whole extent and is
    /// decrypted in place. The result is a *candidate* — the caller must
    /// still check it against a [`Digest`].
    pub fn unwrap_master_key(
        &self,
        passphrase: &[u8],
        encrypted_material: &mut [u8],
    ) -> Result<Vec<u8>> {
        if self.kind != "luks2" {
            return Err(crate::Error::Unsupported(format!(
                "luks2: keyslot type `{}` is not a passphrase slot",
                self.kind
            )));
        }
        if self.af.kind != "luks1" {
            return Err(crate::Error::Unsupported(format!(
                "luks2: anti-forensic splitter type `{}` is not implemented",
                self.af.kind
            )));
        }
        if self.area.kind != "raw" {
            return Err(crate::Error::Unsupported(format!(
                "luks2: keyslot area type `{}` is not implemented",
                self.area.kind
            )));
        }
        let exact = self.key_size * self.af.stripes as usize;
        if encrypted_material.len() < exact {
            return Err(crate::Error::InvalidImage(format!(
                "luks2: keyslot material is {} bytes, need {exact}",
                encrypted_material.len()
            )));
        }

        let mut area_key = vec![0u8; self.area.key_size];
        self.kdf.derive(passphrase, &mut area_key)?;
        let spec = CipherSpec::parse(&self.area.encryption, self.area.key_size)?;
        SectorCipher::new(spec, &area_key, 512)?.decrypt(0, encrypted_material)?;

        af::merge(
            hash::parse(&self.af.hash)?,
            &encrypted_material[..exact],
            self.key_size,
            self.af.stripes,
        )
    }
}

impl Digest {
    /// Does `mk` match this digest?
    pub fn matches(&self, mk: &[u8]) -> Result<bool> {
        if self.kind != "pbkdf2" {
            return Err(crate::Error::Unsupported(format!(
                "luks2: digest type `{}` is not implemented",
                self.kind
            )));
        }
        let salt = base64::decode(&self.salt)?;
        let want = base64::decode(&self.digest)?;
        if want.is_empty() {
            return Err(crate::Error::InvalidImage(
                "luks2: digest field is empty".into(),
            ));
        }
        let mut got = vec![0u8; want.len()];
        hash::pbkdf2(
            hash::parse(&self.hash)?,
            mk,
            &salt,
            self.iterations,
            &mut got,
        )?;
        Ok(super::v1::constant_time_eq(&got, &want))
    }

    /// Compute the digest value for `mk`, base64-encoded — what
    /// [`matches`](Self::matches) would compare against. Used when
    /// formatting a fresh volume.
    pub fn compute(
        alg: HashAlgorithm,
        mk: &[u8],
        salt: &[u8],
        iterations: u32,
        len: usize,
    ) -> Result<String> {
        let mut got = vec![0u8; len];
        hash::pbkdf2(alg, mk, salt, iterations, &mut got)?;
        Ok(base64::encode(&got))
    }
}

fn u64_be(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(buf[off..off + 8].try_into().unwrap())
}

fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|&c| c == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn put_cstr(field: &mut [u8], s: &str) {
    field.fill(0);
    let n = s.len().min(field.len());
    field[..n].copy_from_slice(&s.as_bytes()[..n]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bin() -> BinHeader {
        BinHeader {
            secondary: false,
            hdr_size: DEFAULT_HDR_BYTES,
            seqid: 3,
            label: String::new(),
            checksum_alg: "sha256".into(),
            salt: [0x11u8; 64],
            uuid: "8b1a0f2e-0000-4000-8000-00000000abcd".into(),
            subsystem: String::new(),
            hdr_offset: 0,
            csum: [0u8; 64],
        }
    }

    const SAMPLE_JSON: &str = r#"{
      "keyslots": {
        "0": {
          "type": "luks2",
          "key_size": 64,
          "af": { "type": "luks1", "stripes": 4000, "hash": "sha256" },
          "area": { "type": "raw", "offset": "32768", "size": "258048",
                    "encryption": "aes-xts-plain64", "key_size": 64 },
          "kdf": { "type": "argon2id", "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
                   "time": 4, "memory": 1048576, "cpus": 4 }
        }
      },
      "tokens": {},
      "segments": {
        "0": { "type": "crypt", "offset": "16777216", "size": "dynamic",
               "iv_tweak": "0", "encryption": "aes-xts-plain64",
               "sector_size": 512 }
      },
      "digests": {
        "0": { "type": "pbkdf2", "keyslots": ["0"], "segments": ["0"],
               "hash": "sha256", "iterations": 1000,
               "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
               "digest": "AAAAAAAAAAAAAAAAAAAAAA==" }
      },
      "config": { "json_size": "12288", "keyslots_size": "16744448" }
    }"#;

    #[test]
    fn parses_a_cryptsetup_shaped_document() {
        let m = Metadata::parse(SAMPLE_JSON).unwrap();
        let slot = &m.keyslots["0"];
        assert_eq!(slot.key_size, 64);
        assert_eq!(slot.af.stripes, 4000);
        assert_eq!(slot.area.offset, 32768);
        assert!(matches!(slot.kdf, Kdf::Argon2id { time: 4, .. }));

        let (id, seg) = m.data_segment().unwrap();
        assert_eq!(id, "0");
        assert_eq!(seg.offset, 16 * 1024 * 1024);
        assert_eq!(seg.size_bytes().unwrap(), None); // dynamic
        assert_eq!(seg.sector_size, 512);
        assert_eq!(m.config.json_size, 12288);
        m.check_supported().unwrap();
    }

    #[test]
    fn metadata_survives_a_json_round_trip() {
        let m = Metadata::parse(SAMPLE_JSON).unwrap();
        let again = Metadata::parse(&m.to_json().unwrap()).unwrap();
        assert_eq!(again.keyslots["0"].key_size, 64);
        assert_eq!(again.segments["0"].offset, 16 * 1024 * 1024);
        assert_eq!(again.config.keyslots_size, 16_744_448);
    }

    #[test]
    fn binary_header_round_trips_and_seals() {
        let h = sample_bin();
        let region = seal(&h, SAMPLE_JSON).unwrap();
        assert_eq!(region.len(), DEFAULT_HDR_BYTES as usize);

        let decoded = BinHeader::decode(&region).unwrap();
        assert_eq!(decoded.hdr_size, DEFAULT_HDR_BYTES);
        assert_eq!(decoded.seqid, 3);
        assert_eq!(decoded.uuid, h.uuid);
        assert!(!decoded.secondary);
        assert!(verify_checksum(&decoded, &region).unwrap());

        // The JSON comes back verbatim.
        assert_eq!(json_text(&region).unwrap(), SAMPLE_JSON);
    }

    #[test]
    fn a_flipped_byte_fails_the_checksum() {
        let mut region = seal(&sample_bin(), SAMPLE_JSON).unwrap();
        region[5000] ^= 0x01;
        let decoded = BinHeader::decode(&region).unwrap();
        assert!(!verify_checksum(&decoded, &region).unwrap());
    }

    #[test]
    fn rejects_foreign_headers() {
        let mut region = seal(&sample_bin(), SAMPLE_JSON).unwrap();
        region[0] = b'X';
        assert!(BinHeader::decode(&region).is_err());

        let mut region = seal(&sample_bin(), SAMPLE_JSON).unwrap();
        region[6..8].copy_from_slice(&1u16.to_be_bytes());
        assert!(BinHeader::decode(&region).is_err());
    }

    #[test]
    fn secondary_magic_is_recognised() {
        let mut h = sample_bin();
        h.secondary = true;
        h.hdr_offset = DEFAULT_HDR_BYTES;
        let region = seal(&h, SAMPLE_JSON).unwrap();
        let d = BinHeader::decode(&region).unwrap();
        assert!(d.secondary);
        assert_eq!(d.hdr_offset, DEFAULT_HDR_BYTES);
        assert!(verify_checksum(&d, &region).unwrap());
    }

    #[test]
    fn rejects_oversized_json() {
        let big = "x".repeat(DEFAULT_HDR_BYTES as usize);
        assert!(seal(&sample_bin(), &big).is_err());
    }

    #[test]
    fn refuses_an_absurd_argon2_memory_cost() {
        let kdf = Kdf::Argon2id {
            salt: base64::encode(&[0u8; 16]),
            time: 1,
            memory: u32::MAX,
            cpus: 1,
        };
        let mut out = [0u8; 32];
        assert!(matches!(
            kdf.derive(b"pw", &mut out),
            Err(crate::Error::InvalidImage(_))
        ));
    }

    #[test]
    fn refuses_an_absurd_keyslot_size() {
        let mut m = Metadata::parse(SAMPLE_JSON).unwrap();
        let slot = m.keyslots.get_mut("0").unwrap();
        slot.af.stripes = u32::MAX;
        assert!(matches!(
            slot.material_extent(),
            Err(crate::Error::InvalidImage(_))
        ));
    }

    #[test]
    fn refuses_a_nonsense_sector_size() {
        for bad in [0u32, 3, 300, 2 * 1024 * 1024] {
            let json =
                SAMPLE_JSON.replace(r#""sector_size": 512"#, &format!(r#""sector_size": {bad}"#));
            let m = Metadata::parse(&json).unwrap();
            let (_, seg) = m.data_segment().unwrap();
            assert!(seg.validate().is_err(), "sector_size {bad} was accepted");
        }
    }

    #[test]
    fn refuses_unmet_requirements() {
        let json = SAMPLE_JSON.replace(
            r#""config": { "json_size": "12288", "keyslots_size": "16744448" }"#,
            r#""config": { "json_size": "12288", "keyslots_size": "16744448",
                 "requirements": { "mandatory": ["online-reencrypt-v2"] } }"#,
        );
        let m = Metadata::parse(&json).unwrap();
        assert!(matches!(
            m.check_supported(),
            Err(crate::Error::Unsupported(_))
        ));
    }

    #[test]
    fn refuses_dm_integrity_segments() {
        let json = SAMPLE_JSON.replace(
            r#""sector_size": 512"#,
            r#""sector_size": 512, "integrity": { "type": "hmac(sha256)" }"#,
        );
        let m = Metadata::parse(&json).unwrap();
        let (_, seg) = m.data_segment().unwrap();
        assert!(matches!(
            seg.cipher_spec(64),
            Err(crate::Error::Unsupported(_))
        ));
    }

    /// PBKDF2 keyslots must derive too — cryptsetup writes them for
    /// `--pbkdf pbkdf2` volumes and for LUKS2 headers converted from LUKS1.
    #[test]
    fn pbkdf2_keyslot_kdf_derives() {
        let kdf = Kdf::Pbkdf2 {
            salt: base64::encode(b"0123456789abcdef"),
            hash: "sha256".into(),
            iterations: 1000,
        };
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        kdf.derive(b"secret", &mut a).unwrap();
        kdf.derive(b"secret", &mut b).unwrap();
        assert_eq!(a, b);
        let mut c = [0u8; 64];
        kdf.derive(b"other", &mut c).unwrap();
        assert_ne!(a, c);
    }
}
