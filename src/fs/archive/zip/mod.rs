//! ZIP archives as an fstool filesystem.
//!
//! - **Read:** a full central-directory scan — robust EOCD search past
//!   a trailing comment, ZIP64 (locator + EOCD record + per-entry
//!   extra field `0x0001`), Unix permissions/symlinks from the
//!   external-attributes field, and the encoding handling in the
//!   `encoding` submodule. Every method id is recognised; the body
//!   decodes when its codec feature is compiled in (`Stored` always,
//!   `Deflate` on `gzip`, then `deflate64`, `bzip2`, `lzma`, `xz`,
//!   `zstd`, and `zip-legacy` for Shrink / Reduce / Implode), otherwise
//!   the member indexes and reading it reports `Unsupported` naming the
//!   feature. Encrypted members, and PPMd (variant I, which compcol
//!   lacks), are refused the same way.
//! - **Write:** streams local headers + bodies at a bumping cursor
//!   (CRC-32 + sizes back-patched after each body), then the central
//!   directory + EOCD on flush. `Stored` and `Deflate` by default, and
//!   `-O compression=` picks Deflate64, bzip2, LZMA, XZ or Zstandard
//!   when its feature is on (the PKZIP 1.x methods have no encoder).
//!   ZIP64 is emitted only when an entry, offset, or count
//!   crosses the 32-bit limits. Names are written per the universal-zip
//!   technique (host = MS-DOS, bit 11 only for true UTF-8).

pub mod crypto;
mod encoding;
mod scan;
mod write;

use crate::Result;
use crate::block::BlockDevice;
use crate::fs::archive::ArchiveFs;

pub const SIG_LOCAL: u32 = 0x0403_4b50;
pub const SIG_CENTRAL: u32 = 0x0201_4b50;
pub const SIG_EOCD: u32 = 0x0605_4b50;
pub const SIG_ZIP64_EOCD: u32 = 0x0606_4b50;
pub const SIG_ZIP64_LOCATOR: u32 = 0x0706_4b50;

pub const METHOD_STORE: u16 = 0;
pub const METHOD_SHRINK: u16 = 1;
// Methods 2–5 are Reduce with factors 1–4.
pub const METHOD_IMPLODE: u16 = 6;
pub const METHOD_DEFLATE: u16 = 8;
pub const METHOD_DEFLATE64: u16 = 9;
pub const METHOD_BZIP2: u16 = 12;
pub const METHOD_LZMA: u16 = 14;
pub const METHOD_ZSTD: u16 = 93;
pub const METHOD_XZ: u16 = 95;
pub const METHOD_PPMD: u16 = 98;
/// WinZip AES: the real method moves into the 0x9901 extra field.
pub const METHOD_AES: u16 = 99;
/// Written at the start of the first volume of a split archive.
pub const SIG_SPLIT: u32 = 0x0807_4b50;

/// Smallest split volume we write — Info-ZIP's floor, so the sets we
/// produce are ones every reader has seen before.
pub const MIN_SPLIT_SIZE: u64 = 64 * 1024;

/// Body compression chosen by the writer. Every method except `Stored`
/// needs its codec feature; see [`Compression::enabled`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Stored,
    /// Method 8, the universal default. `gzip`.
    Deflate,
    /// Method 9. `deflate64`.
    Deflate64,
    /// Method 12. `bzip2`.
    Bzip2,
    /// Method 14, written with an end-of-stream marker. `lzma`.
    Lzma,
    /// Method 95. `xz`.
    Xz,
    /// Method 93. `zstd`.
    Zstd,
}

impl Compression {
    /// The `compression=` option spelling, and the name used in errors.
    pub fn name(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Deflate => "deflate",
            Self::Deflate64 => "deflate64",
            Self::Bzip2 => "bzip2",
            Self::Lzma => "lzma",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
        }
    }

    /// The Cargo feature that compiles the encoder in (`None` for
    /// `Stored`).
    pub fn feature(self) -> Option<&'static str> {
        match self {
            Self::Stored => None,
            Self::Deflate => Some("gzip"),
            Self::Deflate64 => Some("deflate64"),
            Self::Bzip2 => Some("bzip2"),
            Self::Lzma => Some("lzma"),
            Self::Xz => Some("xz"),
            Self::Zstd => Some("zstd"),
        }
    }

    /// Whether this build can encode the method.
    pub fn enabled(self) -> bool {
        match self {
            Self::Stored => true,
            Self::Deflate => cfg!(feature = "gzip"),
            Self::Deflate64 => cfg!(feature = "deflate64"),
            Self::Bzip2 => cfg!(feature = "bzip2"),
            Self::Lzma => cfg!(feature = "lzma"),
            Self::Xz => cfg!(feature = "xz"),
            Self::Zstd => cfg!(feature = "zstd"),
        }
    }

    /// The zip method id.
    pub fn method_id(self) -> u16 {
        match self {
            Self::Stored => METHOD_STORE,
            Self::Deflate => METHOD_DEFLATE,
            Self::Deflate64 => METHOD_DEFLATE64,
            Self::Bzip2 => METHOD_BZIP2,
            Self::Lzma => METHOD_LZMA,
            Self::Xz => METHOD_XZ,
            Self::Zstd => METHOD_ZSTD,
        }
    }

    /// The "version needed to extract" APPNOTE assigns the method
    /// (2.0 for Stored / Deflate, 2.1 Deflate64, 4.6 bzip2, 6.3 the
    /// rest).
    pub fn version_needed(self) -> u16 {
        match self {
            Self::Stored | Self::Deflate => 20,
            Self::Deflate64 => 21,
            Self::Bzip2 => 46,
            Self::Lzma | Self::Xz | Self::Zstd => 63,
        }
    }

    fn parse(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "store" | "stored" | "none" => Self::Stored,
            "deflate" | "deflated" => Self::Deflate,
            "deflate64" | "enhanced-deflate" => Self::Deflate64,
            "bzip2" | "bz2" => Self::Bzip2,
            "lzma" => Self::Lzma,
            "xz" => Self::Xz,
            "zstd" | "zst" | "zstandard" => Self::Zstd,
            _ => return None,
        })
    }
}

/// Encryption scheme the writer applies when a passphrase is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    /// Traditional PKWARE encryption. Weak (known-plaintext attacks are
    /// practical) but read by everything since 1990.
    ZipCrypto,
    /// WinZip AES-128 / 192 / 256 (`zip-aes`). Read by 7-Zip, WinZip,
    /// WinRAR, libarchive, Python's `pyzipper` — not by Info-ZIP's
    /// `unzip` 6.0.
    Aes128,
    Aes192,
    Aes256,
}

impl Encryption {
    pub fn name(self) -> &'static str {
        match self {
            Self::ZipCrypto => "zipcrypto",
            Self::Aes128 => "aes128",
            Self::Aes192 => "aes192",
            Self::Aes256 => "aes256",
        }
    }

    /// AES key size, `None` for ZipCrypto.
    pub fn key_bits(self) -> Option<u16> {
        match self {
            Self::ZipCrypto => None,
            Self::Aes128 => Some(128),
            Self::Aes192 => Some(192),
            Self::Aes256 => Some(256),
        }
    }

    pub fn enabled(self) -> bool {
        self == Self::ZipCrypto || cfg!(feature = "zip-aes")
    }

    fn parse(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "zipcrypto" | "pkware" | "traditional" => Self::ZipCrypto,
            "aes128" | "aes-128" => Self::Aes128,
            "aes192" | "aes-192" => Self::Aes192,
            "aes256" | "aes-256" | "aes" => Self::Aes256,
            _ => return None,
        })
    }
}

/// ZIP creation options.
#[derive(Debug, Clone)]
pub struct ZipFormatOpts {
    pub method: Compression,
    /// Compression level 0..=9 (6 = default), in the codec's own scale:
    /// DEFLATE / Deflate64 / LZMA / XZ levels 1–9 (0 is treated as 1),
    /// the bzip2 block size in 100 kB units, and for Zstandard the
    /// level 1–9 of its 1–22 range.
    pub level: u32,
    /// Encrypt every file body with this passphrase (directories and
    /// symlink targets stay in the clear, as every zip tool does).
    pub password: Option<String>,
    /// Scheme used when `password` is set.
    pub encryption: Encryption,
    /// Write a split archive with volumes of at most this many bytes
    /// (≥ [`MIN_SPLIT_SIZE`]). The writer lays the volumes out back to
    /// back and reports their boundaries through
    /// [`ZipFs::volume_layout`]; the caller cuts the file into
    /// `name.z01`, `name.z02`, … and the final `name.zip`.
    pub split: Option<u64>,
}

impl Default for ZipFormatOpts {
    fn default() -> Self {
        Self {
            method: Compression::Deflate,
            level: 6,
            password: None,
            encryption: Encryption::Aes256,
            split: None,
        }
    }
}

impl ZipFormatOpts {
    pub fn apply_options(&mut self, bag: &mut crate::format_opts::OptionMap) -> Result<()> {
        if let Some(c) = bag.take_str("compression") {
            let method = Compression::parse(&c).ok_or_else(|| {
                crate::Error::InvalidArgument(format!(
                    "zip: unknown compression {c:?} (use `stored`, `deflate`, `deflate64`, \
                     `bzip2`, `lzma`, `xz` or `zstd`)"
                ))
            })?;
            // An explicit request for a codec this build lacks is an
            // error, not a silent fall-back to Stored — the caller asked
            // for that method for a reason.
            if !method.enabled() {
                return Err(crate::Error::Unsupported(format!(
                    "zip: {} compression is disabled — rebuild with `--features {}`",
                    method.name(),
                    method.feature().unwrap_or_default()
                )));
            }
            self.method = method;
        }
        if let Some(l) = bag.take_u32("level")? {
            if l > 9 {
                return Err(crate::Error::InvalidArgument(format!(
                    "zip: compression level {l} out of range (0..=9)"
                )));
            }
            self.level = l;
        }
        // `-O password=` is a convenience for scripts and specs; the CLI's
        // `--password` / `--password-file` set the same field without
        // putting the secret in `ps` output.
        if let Some(p) = bag.take_str("password") {
            self.password = Some(p);
        }
        if let Some(e) = bag.take_str("encryption") {
            let enc = Encryption::parse(&e).ok_or_else(|| {
                crate::Error::InvalidArgument(format!(
                    "zip: unknown encryption {e:?} (use `zipcrypto`, `aes128`, `aes192` or `aes256`)"
                ))
            })?;
            if !enc.enabled() {
                return Err(crate::Error::Unsupported(format!(
                    "zip: {} encryption is disabled — rebuild with `--features zip-aes`",
                    enc.name()
                )));
            }
            self.encryption = enc;
        }
        if let Some(sz) = bag.take_size("split")? {
            if sz < MIN_SPLIT_SIZE {
                return Err(crate::Error::InvalidArgument(format!(
                    "zip: split volume size {sz} is below the {MIN_SPLIT_SIZE}-byte minimum"
                )));
            }
            self.split = Some(sz);
        }
        if self.password.is_some() && !self.encryption.enabled() {
            return Err(crate::Error::Unsupported(format!(
                "zip: {} encryption is disabled — rebuild with `--features zip-aes` or pick \
                 `encryption=zipcrypto`",
                self.encryption.name()
            )));
        }
        Ok(())
    }
}

/// ZIP filesystem handle.
pub struct ZipFs(pub ArchiveFs);

impl ZipFs {
    /// Index the archive. Encrypted members list but refuse to read until
    /// a passphrase is supplied via [`open_with_password`](Self::open_with_password).
    pub fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        Self::open_with_password(dev, None)
    }

    /// [`open`](Self::open) with the passphrase for encrypted members.
    /// A wrong one is reported per member, on read, by the scheme's own
    /// check (ZipCrypto's check byte, AES's verifier).
    pub fn open_with_password(dev: &mut dyn BlockDevice, password: Option<&str>) -> Result<Self> {
        let pw = password.map(str::as_bytes);
        Ok(Self(
            ArchiveFs::from_index(scan::scan(dev, pw)?).with_password(password),
        ))
    }

    /// After `flush` on a handle created with `split`: the byte ranges
    /// of the volumes in the linear output, in order. `None` for an
    /// unsplit archive.
    pub fn volume_layout(&self) -> Option<Vec<(u64, u64)>> {
        self.0.volume_layout()
    }

    pub fn format(dev: &mut dyn BlockDevice, opts: &ZipFormatOpts) -> Result<Self> {
        Ok(Self(ArchiveFs::writer(
            "zip",
            Box::new(write::ZipWriter::new(dev, opts.clone())),
        )))
    }
}

impl crate::fs::FilesystemFactory for ZipFs {
    type FormatOpts = ZipFormatOpts;
    fn format(dev: &mut dyn BlockDevice, opts: &Self::FormatOpts) -> Result<Self> {
        Self::format(dev, opts)
    }
    fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        Self::open(dev)
    }
    fn volume_layout(&self) -> Option<Vec<(u64, u64)>> {
        ZipFs::volume_layout(self)
    }
}

crate::impl_archive_fs_filesystem!(ZipFs);

/// Convert a DOS date+time pair to seconds since the Unix epoch (UTC).
/// DOS time has 2-second resolution and a 1980 epoch.
pub(crate) fn dos_to_unix(dos_date: u16, dos_time: u16) -> u64 {
    let sec = ((dos_time & 0x1f) as u64) * 2;
    let min = ((dos_time >> 5) & 0x3f) as u64;
    let hour = ((dos_time >> 11) & 0x1f) as u64;
    let day = (dos_date & 0x1f) as u64;
    let month = ((dos_date >> 5) & 0x0f) as u64;
    let year = 1980 + ((dos_date >> 9) & 0x7f) as u64;
    days_from_civil(year, month.max(1), day.max(1)) * 86400 + hour * 3600 + min * 60 + sec
}

/// Convert seconds since the Unix epoch (UTC) to a DOS date+time pair.
/// Clamps below the 1980 epoch.
pub(crate) fn unix_to_dos(secs: u64) -> (u16, u16) {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (year, month, day) = civil_from_days(days);
    if year < 1980 {
        // DOS epoch floor: 1980-01-01 00:00:00.
        return (0x0021, 0);
    }
    let hour = (rem / 3600) as u16;
    let min = ((rem % 3600) / 60) as u16;
    let sec2 = ((rem % 60) / 2) as u16;
    let date = (((year - 1980) as u16) << 9) | ((month as u16) << 5) | (day as u16);
    let time = (hour << 11) | (min << 5) | sec2;
    (date, time)
}

/// Days from 1970-01-01 to `y-m-d` (Howard Hinnant's algorithm).
fn days_from_civil(y: u64, m: u64, d: u64) -> u64 {
    let y = if m <= 2 { y - 1 } else { y } as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = ((m + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146097 + doe - 719468) as u64
}

/// Inverse of [`days_from_civil`]: civil `(year, month, day)` from a
/// day count since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u64, u64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u64;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u64;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_time_round_trips() {
        // 2021-06-15 12:30:44 UTC.
        let secs = days_from_civil(2021, 6, 15) * 86400 + 12 * 3600 + 30 * 60 + 44;
        let (date, time) = unix_to_dos(secs);
        // DOS seconds have 2s resolution → 44 stays 44.
        assert_eq!(dos_to_unix(date, time), secs);
    }

    #[test]
    fn pre_1980_clamps() {
        let (date, time) = unix_to_dos(0); // 1970
        assert_eq!((date, time), (0x0021, 0));
    }
}
