//! Sector-addressed disk encryption — the cipher engine shared by LUKS
//! and qcow2.
//!
//! Full-disk encryption schemes all have the same shape: the volume is cut
//! into fixed-size *sectors*, each sector is encrypted independently, and
//! the sector's index feeds an *IV generator* so identical plaintext at
//! different offsets encrypts differently. dm-crypt (and therefore LUKS)
//! spells the whole arrangement as one string:
//!
//! ```text
//!     aes    -    xts   -   plain64
//!     ^^^         ^^^       ^^^^^^^
//!     cipher      mode      IV generator
//! ```
//!
//! [`CipherSpec::parse`] turns that string into a spec, and
//! [`SectorCipher::new`] keys it. From then on the caller works in whole
//! sectors: [`SectorCipher::decrypt`] and [`SectorCipher::encrypt`] take a
//! buffer of *n* consecutive sectors plus the index of the first one.
//!
//! ## What is implemented
//!
//! - **Ciphers** — the four 128-bit-block ciphers `purecrypto` provides:
//!   `aes`, `camellia`, `aria` (128/192/256-bit keys each) and `sm4`
//!   (128-bit). `serpent` and `twofish` are recognised well enough to
//!   produce a precise [`crate::Error::Unsupported`] rather than a
//!   confusing parse failure.
//! - **Modes** — `xts` (the modern default; the key is split in half into
//!   a data key and a tweak key), `cbc`, `ctr` and `ecb`.
//! - **IV generators** — `plain`, `plain64`, `plain64be`, `benbi`,
//!   `null`, and `essiv:<hash>` for `sha1` / `sha256` / `sha512` /
//!   `ripemd160`. XTS takes the sector index directly as its tweak and
//!   ignores the IV generator, which is why `aes-xts-plain64` and
//!   `aes-xts-plain` decrypt identically.
//!
//! ## Integrity
//!
//! None of these modes authenticate. A corrupted or tampered sector
//! decrypts to garbage rather than failing — exactly as it does under
//! dm-crypt. LUKS's own integrity story (`--integrity`, the `dm-integrity`
//! layer underneath) is a separate on-disk format and is not implemented;
//! [`crate::block::luks`] rejects volumes that ask for it.

use purecrypto::cipher::{
    Aes128, Aes192, Aes256, Aria128, Aria192, Aria256, Camellia128, Camellia192, Camellia256, Cbc,
    Ctr, Sm4, Xts,
};
use purecrypto::hash::HashAlgorithm;

use super::hash;
use crate::Result;

/// The block cipher underneath the mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algo {
    /// AES (Rijndael), 128/192/256-bit keys. The cryptsetup default.
    Aes,
    /// Camellia, 128/192/256-bit keys.
    Camellia,
    /// ARIA, 128/192/256-bit keys.
    Aria,
    /// SM4, 128-bit keys only.
    Sm4,
}

impl Algo {
    fn name(self) -> &'static str {
        match self {
            Algo::Aes => "aes",
            Algo::Camellia => "camellia",
            Algo::Aria => "aria",
            Algo::Sm4 => "sm4",
        }
    }
}

/// Chaining mode applied within a sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// XEX-based tweaked codebook with ciphertext stealing (IEEE 1619).
    /// Consumes *twice* the cipher's key length: the first half keys the
    /// data cipher, the second half the tweak cipher.
    Xts,
    /// Cipher block chaining, restarted at every sector with the IV the
    /// generator produces.
    Cbc,
    /// Counter mode, seeded per sector from the IV generator.
    Ctr,
    /// Raw ECB — no IV at all. Present because dm-crypt accepts it; it
    /// leaks plaintext equality between blocks and should not be chosen
    /// for anything new.
    Ecb,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Xts => "xts",
            Mode::Cbc => "cbc",
            Mode::Ctr => "ctr",
            Mode::Ecb => "ecb",
        }
    }
}

/// How the per-sector IV is derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IvGen {
    /// 32-bit little-endian sector index in the first 4 bytes, rest zero.
    Plain,
    /// 64-bit little-endian sector index in the first 8 bytes, rest zero.
    Plain64,
    /// 64-bit big-endian sector index in the *last* 8 bytes, rest zero.
    Plain64Be,
    /// `(sector << shift) + 1` big-endian in the last 8 bytes, where
    /// `shift = log2(sector_size / 16)`. Numbers each cipher block of the
    /// volume from 1 rather than each sector.
    Benbi,
    /// All-zero IV.
    Null,
    /// Encrypted salt-sector IV: `IV = E_salt(plain64)` where the salt key
    /// is `hash(master_key)`. The digest length therefore has to be a legal
    /// key length for the cipher — `essiv:sha256` with AES, in practice.
    Essiv(HashAlgorithm),
}

impl IvGen {
    fn name(self) -> String {
        match self {
            IvGen::Plain => "plain".into(),
            IvGen::Plain64 => "plain64".into(),
            IvGen::Plain64Be => "plain64be".into(),
            IvGen::Benbi => "benbi".into(),
            IvGen::Null => "null".into(),
            IvGen::Essiv(h) => format!("essiv:{}", h.name()),
        }
    }
}

/// A parsed `cipher-mode-ivgen` specification plus its key length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherSpec {
    pub algo: Algo,
    pub mode: Mode,
    pub ivgen: IvGen,
    /// Total key length in bytes, as the container records it. For XTS
    /// this counts *both* halves.
    pub key_bytes: usize,
}

impl CipherSpec {
    /// Parse a dm-crypt cipher string — `"aes-xts-plain64"`,
    /// `"aes-cbc-essiv:sha256"`, `"aes-ecb"` — together with the key
    /// length the container declares.
    ///
    /// LUKS1 splits the string in two on disk (`cipher-name` = `"aes"`,
    /// `cipher-mode` = `"xts-plain64"`); join them with a `-` and pass the
    /// result here. LUKS2 and qcow2 already store it joined.
    pub fn parse(spec: &str, key_bytes: usize) -> Result<Self> {
        let mut parts = spec.split('-');
        let cipher = parts.next().unwrap_or("");
        let mode = parts.next().unwrap_or("");
        // The IV generator may itself contain a `-` (none in practice, but
        // `essiv:sha256` does contain a `:`), so take everything left.
        let ivspec: Vec<&str> = parts.collect();
        let ivspec = ivspec.join("-");

        let algo = match cipher {
            "aes" => Algo::Aes,
            "camellia" => Algo::Camellia,
            "aria" => Algo::Aria,
            "sm4" => Algo::Sm4,
            "serpent" | "twofish" | "cast5" | "cast6" | "blowfish" => {
                return Err(crate::Error::Unsupported(format!(
                    "crypt: cipher `{cipher}` is not implemented (purecrypto offers \
                     aes, camellia, aria and sm4)"
                )));
            }
            other => {
                return Err(crate::Error::Unsupported(format!(
                    "crypt: unknown cipher `{other}` in spec `{spec}`"
                )));
            }
        };

        let mode = match mode {
            "xts" => Mode::Xts,
            "cbc" => Mode::Cbc,
            "ctr" => Mode::Ctr,
            "ecb" => Mode::Ecb,
            "lrw" | "xex" => {
                return Err(crate::Error::Unsupported(format!(
                    "crypt: mode `{mode}` is not implemented"
                )));
            }
            other => {
                return Err(crate::Error::Unsupported(format!(
                    "crypt: unknown mode `{other}` in spec `{spec}`"
                )));
            }
        };

        // ECB takes no IV generator; every other mode requires one, except
        // XTS which tolerates a missing one (the tweak is the sector index).
        let ivgen = match ivspec.as_str() {
            "" if matches!(mode, Mode::Ecb | Mode::Xts) => IvGen::Null,
            "" => {
                return Err(crate::Error::InvalidImage(format!(
                    "crypt: spec `{spec}` names mode `{}` but no IV generator",
                    mode.name()
                )));
            }
            "plain" => IvGen::Plain,
            "plain64" => IvGen::Plain64,
            "plain64be" => IvGen::Plain64Be,
            "benbi" => IvGen::Benbi,
            "null" => IvGen::Null,
            other => match other.strip_prefix("essiv:") {
                Some(h) => IvGen::Essiv(hash::parse(h)?),
                None => {
                    return Err(crate::Error::Unsupported(format!(
                        "crypt: unknown IV generator `{other}` in spec `{spec}`"
                    )));
                }
            },
        };

        let spec = Self {
            algo,
            mode,
            ivgen,
            key_bytes,
        };
        spec.validate_key_len()?;
        Ok(spec)
    }

    /// Render back to the dm-crypt string this spec parsed from.
    pub fn to_spec_string(&self) -> String {
        match self.mode {
            Mode::Ecb => format!("{}-ecb", self.algo.name()),
            _ => format!(
                "{}-{}-{}",
                self.algo.name(),
                self.mode.name(),
                self.ivgen.name()
            ),
        }
    }

    /// The key length one cipher instance consumes — half of `key_bytes`
    /// under XTS, all of it otherwise.
    fn cipher_key_bytes(&self) -> usize {
        match self.mode {
            Mode::Xts => self.key_bytes / 2,
            _ => self.key_bytes,
        }
    }

    fn validate_key_len(&self) -> Result<()> {
        if matches!(self.mode, Mode::Xts) && !self.key_bytes.is_multiple_of(2) {
            return Err(crate::Error::InvalidImage(format!(
                "crypt: XTS needs an even key length, got {} bytes",
                self.key_bytes
            )));
        }
        let per = self.cipher_key_bytes();
        let ok = match self.algo {
            Algo::Aes | Algo::Camellia | Algo::Aria => matches!(per, 16 | 24 | 32),
            Algo::Sm4 => per == 16,
        };
        if !ok {
            return Err(crate::Error::InvalidImage(format!(
                "crypt: {} does not take a {}-byte key (total key length {})",
                self.algo.name(),
                per,
                self.key_bytes
            )));
        }
        Ok(())
    }
}

// One `purecrypto` block cipher per (algorithm, key length) pair, plus the
// XTS wrapper around the same set. `Xts<C>` is generic over a *sized*
// `BlockCipher`, and `BlockCipher` carries associated consts so it is not
// object safe — hence a pair of parallel enums generated from one table
// rather than a `Box<dyn BlockCipher>`.
macro_rules! block_ciphers {
    ($( $variant:ident => ($ty:ty, $algo:expr, $klen:literal) ),+ $(,)?) => {
        /// A keyed block cipher, one variant per (algorithm, key length).
        enum Block { $( $variant($ty), )+ }

        /// An XTS context over the same set. Holds two independently keyed
        /// ciphers of the same type (data key, tweak key).
        enum XtsCipher { $( $variant(Xts<$ty>), )+ }

        impl Block {
            fn new(algo: Algo, key: &[u8]) -> Result<Self> {
                $(
                    if algo == $algo && key.len() == $klen {
                        let k: &[u8; $klen] = key.try_into().expect("length just checked");
                        return Ok(Block::$variant(<$ty>::new(k)));
                    }
                )+
                Err(crate::Error::InvalidImage(format!(
                    "crypt: {} does not take a {}-byte key",
                    algo.name(),
                    key.len()
                )))
            }

            fn encrypt_block(&self, b: &mut [u8; 16]) {
                use purecrypto::cipher::BlockCipher as _;
                match self { $( Block::$variant(c) => c.encrypt_block(b), )+ }
            }

            fn decrypt_block(&self, b: &mut [u8; 16]) {
                use purecrypto::cipher::BlockCipher as _;
                match self { $( Block::$variant(c) => c.decrypt_block(b), )+ }
            }

            /// A fresh CBC chain seeded with `iv`. The keyed cipher is
            /// cheap to clone (it is just the expanded key schedule), and
            /// every sector needs its own chain.
            fn cbc(&self, iv: &[u8; 16]) -> CbcCtx {
                match self { $( Block::$variant(c) => CbcCtx::$variant(Cbc::new(c.clone(), iv)), )+ }
            }

            /// A fresh CTR stream seeded with `iv`.
            fn ctr(&self, iv: &[u8; 16]) -> CtrCtx {
                match self { $( Block::$variant(c) => CtrCtx::$variant(Ctr::new(c.clone(), iv)), )+ }
            }
        }

        /// A per-sector CBC chain.
        enum CbcCtx { $( $variant(Cbc<$ty>), )+ }
        /// A per-sector CTR stream.
        enum CtrCtx { $( $variant(Ctr<$ty>), )+ }

        impl CbcCtx {
            fn encrypt(&mut self, buf: &mut [u8]) -> Result<()> {
                match self { $( CbcCtx::$variant(c) => c.encrypt(buf).map_err(cbc_err), )+ }
            }
            fn decrypt(&mut self, buf: &mut [u8]) -> Result<()> {
                match self { $( CbcCtx::$variant(c) => c.decrypt(buf).map_err(cbc_err), )+ }
            }
        }

        impl CtrCtx {
            fn apply(&mut self, buf: &mut [u8]) {
                match self { $( CtrCtx::$variant(c) => c.apply_keystream(buf), )+ }
            }
        }

        impl XtsCipher {
            fn new(algo: Algo, data_key: &[u8], tweak_key: &[u8]) -> Result<Self> {
                $(
                    if algo == $algo && data_key.len() == $klen && tweak_key.len() == $klen {
                        let d: &[u8; $klen] = data_key.try_into().expect("length just checked");
                        let t: &[u8; $klen] = tweak_key.try_into().expect("length just checked");
                        return Ok(XtsCipher::$variant(Xts::new(<$ty>::new(d), <$ty>::new(t))));
                    }
                )+
                Err(crate::Error::InvalidImage(format!(
                    "crypt: {}-xts does not take {}-byte half-keys",
                    algo.name(),
                    data_key.len()
                )))
            }

            fn encrypt_sector(&self, index: u128, buf: &mut [u8]) -> Result<()> {
                match self {
                    $( XtsCipher::$variant(c) => c.encrypt_sector(index, buf).map_err(xts_err), )+
                }
            }

            fn decrypt_sector(&self, index: u128, buf: &mut [u8]) -> Result<()> {
                match self {
                    $( XtsCipher::$variant(c) => c.decrypt_sector(index, buf).map_err(xts_err), )+
                }
            }
        }
    };
}

block_ciphers! {
    Aes128 => (Aes128, Algo::Aes, 16),
    Aes192 => (Aes192, Algo::Aes, 24),
    Aes256 => (Aes256, Algo::Aes, 32),
    Camellia128 => (Camellia128, Algo::Camellia, 16),
    Camellia192 => (Camellia192, Algo::Camellia, 24),
    Camellia256 => (Camellia256, Algo::Camellia, 32),
    Aria128 => (Aria128, Algo::Aria, 16),
    Aria192 => (Aria192, Algo::Aria, 24),
    Aria256 => (Aria256, Algo::Aria, 32),
    Sm4 => (Sm4, Algo::Sm4, 16),
}

fn cbc_err(e: purecrypto::cipher::InvalidLength) -> crate::Error {
    crate::Error::InvalidImage(format!("crypt: cbc: {e}"))
}

fn xts_err(e: purecrypto::cipher::InvalidLength) -> crate::Error {
    crate::Error::InvalidImage(format!("crypt: xts: {e}"))
}

/// Keyed engine over one [`CipherSpec`], addressed in whole sectors.
pub struct SectorCipher {
    spec: CipherSpec,
    sector_size: u32,
    /// XTS context, or `None` for the chaining modes.
    xts: Option<XtsCipher>,
    /// Data cipher for CBC / CTR / ECB, or `None` under XTS.
    block: Option<Block>,
    /// ESSIV salt cipher, keyed with `hash(master_key)`.
    essiv: Option<Block>,
    /// `log2(sector_size / 16)` — the `benbi` generator's shift.
    benbi_shift: u32,
}

impl std::fmt::Debug for SectorCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SectorCipher")
            .field("spec", &self.spec.to_spec_string())
            .field("key_bytes", &self.spec.key_bytes)
            .field("sector_size", &self.sector_size)
            .finish()
    }
}

impl SectorCipher {
    /// Key the engine. `key.len()` must equal `spec.key_bytes`, and
    /// `sector_size` must be a power of two of at least 16 bytes (the
    /// cipher block size).
    pub fn new(spec: CipherSpec, key: &[u8], sector_size: u32) -> Result<Self> {
        if key.len() != spec.key_bytes {
            return Err(crate::Error::InvalidImage(format!(
                "crypt: key is {} bytes, spec declares {}",
                key.len(),
                spec.key_bytes
            )));
        }
        if !sector_size.is_power_of_two() || sector_size < 16 {
            return Err(crate::Error::InvalidImage(format!(
                "crypt: sector size {sector_size} must be a power of two ≥ 16"
            )));
        }

        let (xts, block) = match spec.mode {
            Mode::Xts => {
                let half = spec.key_bytes / 2;
                (
                    Some(XtsCipher::new(spec.algo, &key[..half], &key[half..])?),
                    None,
                )
            }
            _ => (None, Some(Block::new(spec.algo, key)?)),
        };

        // ESSIV keys a second cipher instance with the digest of the master
        // key, so the digest length has to be a legal key length for the
        // algorithm. cryptsetup enforces the same pairing.
        let essiv = match spec.ivgen {
            IvGen::Essiv(h) => {
                let salt = h.digest(key);
                Some(Block::new(spec.algo, salt.as_slice()).map_err(|_| {
                    crate::Error::Unsupported(format!(
                        "crypt: essiv:{} yields a {}-byte salt key, which {} does not accept",
                        h.name(),
                        salt.len(),
                        spec.algo.name()
                    ))
                })?)
            }
            _ => None,
        };

        Ok(Self {
            spec,
            sector_size,
            xts,
            block,
            essiv,
            benbi_shift: (sector_size / 16).trailing_zeros(),
        })
    }

    /// The spec this engine was keyed from.
    pub fn spec(&self) -> &CipherSpec {
        &self.spec
    }

    /// Sector size in bytes.
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// Build the 16-byte IV for `sector`.
    fn iv(&self, sector: u64) -> [u8; 16] {
        let mut iv = [0u8; 16];
        match self.spec.ivgen {
            IvGen::Null => {}
            IvGen::Plain => iv[..4].copy_from_slice(&(sector as u32).to_le_bytes()),
            IvGen::Plain64 => iv[..8].copy_from_slice(&sector.to_le_bytes()),
            IvGen::Plain64Be => iv[8..].copy_from_slice(&sector.to_be_bytes()),
            IvGen::Benbi => {
                // dm-crypt numbers cipher blocks from 1 across the volume.
                let val = (sector << self.benbi_shift).wrapping_add(1);
                iv[8..].copy_from_slice(&val.to_be_bytes());
            }
            IvGen::Essiv(_) => {
                iv[..8].copy_from_slice(&sector.to_le_bytes());
                self.essiv
                    .as_ref()
                    .expect("essiv cipher keyed alongside the ivgen")
                    .encrypt_block(&mut iv);
            }
        }
        iv
    }

    /// Decrypt `buf` in place. `buf` holds whole consecutive sectors
    /// starting at `first_sector`; its length must be a multiple of
    /// [`sector_size`](Self::sector_size).
    pub fn decrypt(&self, first_sector: u64, buf: &mut [u8]) -> Result<()> {
        self.apply(first_sector, buf, false)
    }

    /// Encrypt `buf` in place. Mirrors [`decrypt`](Self::decrypt).
    pub fn encrypt(&self, first_sector: u64, buf: &mut [u8]) -> Result<()> {
        self.apply(first_sector, buf, true)
    }

    fn apply(&self, first_sector: u64, buf: &mut [u8], encrypt: bool) -> Result<()> {
        let ss = self.sector_size as usize;
        if !buf.len().is_multiple_of(ss) {
            return Err(crate::Error::InvalidArgument(format!(
                "crypt: buffer of {} bytes is not a whole number of {ss}-byte sectors",
                buf.len()
            )));
        }
        for (i, sector) in buf.chunks_exact_mut(ss).enumerate() {
            let index = first_sector.checked_add(i as u64).ok_or_else(|| {
                crate::Error::InvalidArgument("crypt: sector index overflows u64".into())
            })?;
            self.apply_one(index, sector, encrypt)?;
        }
        Ok(())
    }

    fn apply_one(&self, index: u64, sector: &mut [u8], encrypt: bool) -> Result<()> {
        match self.spec.mode {
            Mode::Xts => {
                // XTS takes the sector index as its tweak directly; the IV
                // generator named in the spec is inert (dm-crypt behaves the
                // same way, which is why `aes-xts-plain` and
                // `aes-xts-plain64` are interchangeable in practice).
                let xts = self.xts.as_ref().expect("xts keyed for Mode::Xts");
                if encrypt {
                    xts.encrypt_sector(index as u128, sector)
                } else {
                    xts.decrypt_sector(index as u128, sector)
                }
            }
            Mode::Cbc => {
                let iv = self.iv(index);
                let block = self.block.as_ref().expect("block keyed for Mode::Cbc");
                let mut ctx = block.cbc(&iv);
                if encrypt {
                    ctx.encrypt(sector)
                } else {
                    ctx.decrypt(sector)
                }
            }
            Mode::Ctr => {
                let iv = self.iv(index);
                let block = self.block.as_ref().expect("block keyed for Mode::Ctr");
                // CTR is its own inverse.
                block.ctr(&iv).apply(sector);
                Ok(())
            }
            Mode::Ecb => {
                let block = self.block.as_ref().expect("block keyed for Mode::Ecb");
                if !sector.len().is_multiple_of(16) {
                    return Err(crate::Error::InvalidArgument(
                        "crypt: ecb needs whole 16-byte blocks".into(),
                    ));
                }
                // The length check above leaves no remainder.
                let (blocks, _) = sector.as_chunks_mut::<16>();
                for b in blocks {
                    if encrypt {
                        block.encrypt_block(b);
                    } else {
                        block.decrypt_block(b);
                    }
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_common_specs() {
        let s = CipherSpec::parse("aes-xts-plain64", 64).unwrap();
        assert_eq!(s.algo, Algo::Aes);
        assert_eq!(s.mode, Mode::Xts);
        assert_eq!(s.ivgen, IvGen::Plain64);
        assert_eq!(s.to_spec_string(), "aes-xts-plain64");

        let s = CipherSpec::parse("aes-cbc-essiv:sha256", 32).unwrap();
        assert_eq!(s.mode, Mode::Cbc);
        assert_eq!(s.ivgen, IvGen::Essiv(HashAlgorithm::Sha256));
        assert_eq!(s.to_spec_string(), "aes-cbc-essiv:sha256");

        let s = CipherSpec::parse("aes-ecb", 32).unwrap();
        assert_eq!(s.mode, Mode::Ecb);
        assert_eq!(s.to_spec_string(), "aes-ecb");
    }

    #[test]
    fn rejects_ciphers_purecrypto_lacks() {
        let err = CipherSpec::parse("serpent-xts-plain64", 64).unwrap_err();
        assert!(matches!(err, crate::Error::Unsupported(_)), "{err}");
        let err = CipherSpec::parse("twofish-cbc-essiv:sha256", 32).unwrap_err();
        assert!(matches!(err, crate::Error::Unsupported(_)), "{err}");
    }

    #[test]
    fn rejects_mismatched_key_lengths() {
        // XTS halves the key, so 32 total is AES-128 per half — fine.
        assert!(CipherSpec::parse("aes-xts-plain64", 32).is_ok());
        // 48 total halves to 24 (AES-192) — legal for AES.
        assert!(CipherSpec::parse("aes-xts-plain64", 48).is_ok());
        // 40 halves to 20, which is no AES key length.
        assert!(CipherSpec::parse("aes-xts-plain64", 40).is_err());
        // Odd totals cannot be halved at all.
        assert!(CipherSpec::parse("aes-xts-plain64", 33).is_err());
        // SM4 is 128-bit only.
        assert!(CipherSpec::parse("sm4-cbc-plain64", 32).is_err());
        assert!(CipherSpec::parse("sm4-cbc-plain64", 16).is_ok());
    }

    /// Every mode must round-trip a multi-sector buffer.
    #[test]
    fn round_trips_every_mode() {
        for (spec_str, key_len) in [
            ("aes-xts-plain64", 64),
            ("aes-xts-plain64", 32),
            ("aes-cbc-essiv:sha256", 32),
            ("aes-cbc-plain64", 16),
            ("aes-cbc-plain", 32),
            ("aes-cbc-plain64be", 32),
            ("aes-cbc-benbi", 32),
            ("aes-ctr-plain64", 32),
            ("aes-ecb", 32),
            ("camellia-xts-plain64", 64),
            ("aria-cbc-plain64", 32),
            ("sm4-cbc-plain64", 16),
        ] {
            let spec = CipherSpec::parse(spec_str, key_len).unwrap();
            let key: Vec<u8> = (0..key_len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let c = SectorCipher::new(spec, &key, 512).unwrap();

            let plain: Vec<u8> = (0..512 * 3).map(|i| (i % 251) as u8).collect();
            let mut buf = plain.clone();
            c.encrypt(9, &mut buf).unwrap();
            assert_ne!(buf, plain, "{spec_str} left the plaintext alone");
            c.decrypt(9, &mut buf).unwrap();
            assert_eq!(buf, plain, "{spec_str} failed to round-trip");
        }
    }

    /// The sector index must actually reach the cipher: the same plaintext
    /// at two sector indices has to encrypt differently. (ECB is the
    /// deliberate exception — it has no IV at all.)
    #[test]
    fn sector_index_diversifies_ciphertext() {
        for (spec_str, key_len) in [
            ("aes-xts-plain64", 64),
            ("aes-cbc-essiv:sha256", 32),
            ("aes-cbc-plain64", 32),
            ("aes-cbc-plain", 32),
            ("aes-cbc-plain64be", 32),
            ("aes-cbc-benbi", 32),
            ("aes-ctr-plain64", 32),
        ] {
            let spec = CipherSpec::parse(spec_str, key_len).unwrap();
            let key = vec![0x5au8; key_len];
            let c = SectorCipher::new(spec, &key, 512).unwrap();
            let mut a = vec![0u8; 512];
            let mut b = vec![0u8; 512];
            c.encrypt(0, &mut a).unwrap();
            c.encrypt(1, &mut b).unwrap();
            assert_ne!(a, b, "{spec_str} ignored the sector index");
        }
    }

    /// A wrong key must not decrypt to the original plaintext.
    #[test]
    fn wrong_key_does_not_recover_plaintext() {
        let spec = CipherSpec::parse("aes-xts-plain64", 64).unwrap();
        let plain = vec![0xa5u8; 512];
        let mut buf = plain.clone();
        SectorCipher::new(spec.clone(), &[1u8; 64], 512)
            .unwrap()
            .encrypt(0, &mut buf)
            .unwrap();
        SectorCipher::new(spec, &[2u8; 64], 512)
            .unwrap()
            .decrypt(0, &mut buf)
            .unwrap();
        assert_ne!(buf, plain);
    }

    #[test]
    fn rejects_partial_sector_buffers() {
        let spec = CipherSpec::parse("aes-xts-plain64", 64).unwrap();
        let c = SectorCipher::new(spec, &[0u8; 64], 512).unwrap();
        let mut buf = vec![0u8; 500];
        assert!(matches!(
            c.encrypt(0, &mut buf),
            Err(crate::Error::InvalidArgument(_))
        ));
    }

    /// IEEE 1619-2007 XTS-AES-128 vector 1 (all-zero key, tweak 0), via the
    /// `aes-xts-plain64` spec — pins our sector-index → tweak wiring to the
    /// published vector, not just to our own round-trip.
    #[test]
    fn matches_ieee1619_xts_vector() {
        let spec = CipherSpec::parse("aes-xts-plain64", 32).unwrap();
        let c = SectorCipher::new(spec, &[0u8; 32], 32).unwrap();
        let mut buf = [0u8; 32];
        c.encrypt(0, &mut buf).unwrap();
        // 917cf69ebd68b2ec9b9fe9a3eadda692 cd43d2f59598ed858c02c2652fbf922e
        let expect = [
            0x91, 0x7c, 0xf6, 0x9e, 0xbd, 0x68, 0xb2, 0xec, 0x9b, 0x9f, 0xe9, 0xa3, 0xea, 0xdd,
            0xa6, 0x92, 0xcd, 0x43, 0xd2, 0xf5, 0x95, 0x98, 0xed, 0x85, 0x8c, 0x02, 0xc2, 0x65,
            0x2f, 0xbf, 0x92, 0x2e,
        ];
        assert_eq!(buf, expect);
    }
}
