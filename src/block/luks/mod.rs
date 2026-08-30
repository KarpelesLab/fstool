//! LUKS — the Linux Unified Key Setup, as a [`BlockDevice`].
//!
//! A LUKS volume is a header plus an encrypted payload. The header stores
//! the volume's *master key* several times over, each copy wrapped under a
//! different passphrase, so a passphrase can be changed or revoked without
//! re-encrypting a single payload byte. [`LuksBackend::open`] walks the
//! keyslots, recovers the master key, and from then on presents the
//! decrypted payload as an ordinary block device — reads decrypt, writes
//! re-encrypt, and every layer above (partition table, filesystem) is
//! none the wiser.
//!
//! ```no_run
//! use fstool::block::{BlockDevice, FileBackend, luks::LuksBackend};
//!
//! let disk = FileBackend::open("secret.img")?;
//! let mut vol = LuksBackend::open(disk, "correct horse battery staple")?;
//! let mut buf = [0u8; 512];
//! vol.read_at(0, &mut buf)?;      // plaintext
//! # Ok::<(), fstool::Error>(())
//! ```
//!
//! ## What is supported
//!
//! - **LUKS1** ([`v1`]) and **LUKS2** ([`v2`]) — detected from the version
//!   field behind the shared `"LUKS\xba\xbe"` magic.
//! - **Unlock** with a passphrase (every keyslot is tried), or directly
//!   with a master key via [`LuksBackend::open_with_master_key`].
//! - **Read and write in place.** Writes stay within the existing payload
//!   and never touch the header, so a volume opened here can still be
//!   opened by `cryptsetup`.
//! - **Format** a fresh volume — see [`format`].
//! - Ciphers, modes and IV generators as far as [`crypt`] implements them
//!   (AES/Camellia/ARIA/SM4 in XTS/CBC/CTR/ECB).
//!
//! ## What is not
//!
//! - **Keyslot management** — adding, changing or killing a passphrase on
//!   an existing volume. [`format`] writes a single slot 0.
//! - **`--integrity` volumes**, which put a `dm-integrity` layer under the
//!   crypt layer, and volumes mid online-re-encryption. Both are refused
//!   on open rather than misread.
//! - **Detached headers** (`cryptsetup --header`). The header is expected
//!   at offset 0 of the device handed in.
//!
//! ## A caution about `sync`
//!
//! None of these modes authenticate (see [`crypt`]). A garbled sector
//! decrypts to garbage rather than raising an error, exactly as it does
//! under dm-crypt.

pub mod af;
pub mod crypt;
pub mod format;
pub mod hash;
pub mod v1;
pub mod v2;

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::Result;

use super::BlockDevice;
use crypt::SectorCipher;

pub use format::{FormatOpts, KdfChoice, format};

/// Which on-disk format a volume uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// LUKS1 — one 592-byte big-endian header, eight fixed keyslots.
    V1,
    /// LUKS2 — a binary header pair plus JSON metadata.
    V2,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Version::V1 => "LUKS1",
            Version::V2 => "LUKS2",
        })
    }
}

/// The decoded header, whichever version it turned out to be.
#[derive(Debug, Clone)]
pub enum Header {
    V1(Box<v1::Header>),
    V2 {
        /// The authoritative binary header copy (highest valid `seqid`).
        bin: Box<v2::BinHeader>,
        meta: Box<v2::Metadata>,
    },
}

impl Header {
    pub fn version(&self) -> Version {
        match self {
            Header::V1(_) => Version::V1,
            Header::V2 { .. } => Version::V2,
        }
    }

    /// The volume UUID as stored in the header.
    pub fn uuid(&self) -> &str {
        match self {
            Header::V1(h) => &h.uuid,
            Header::V2 { bin, .. } => &bin.uuid,
        }
    }

    /// The payload's dm-crypt cipher string, e.g. `"aes-xts-plain64"`.
    pub fn cipher_spec_string(&self) -> Result<String> {
        match self {
            Header::V1(h) => Ok(h.cipher_spec_string()),
            Header::V2 { meta, .. } => Ok(meta.data_segment()?.1.encryption.clone()),
        }
    }
}

/// Peek at `buf` (at least 8 bytes from offset 0 of a device) and report
/// which LUKS version it is, if any.
pub fn detect(buf: &[u8]) -> Option<Version> {
    if buf.len() < 8 || buf[0..6] != v1::LUKS_MAGIC {
        return None;
    }
    match u16::from_be_bytes([buf[6], buf[7]]) {
        1 => Some(Version::V1),
        2 => Some(Version::V2),
        _ => None,
    }
}

/// Read the first sector of `dev` and report which LUKS version it holds.
/// Any I/O failure or short device reads as "not LUKS" so callers can fall
/// through to other backends.
pub fn probe<B: BlockDevice + ?Sized>(dev: &mut B) -> Option<Version> {
    let mut head = [0u8; 8];
    dev.read_at(0, &mut head).ok()?;
    detect(&head)
}

/// Master key material that is wiped when it goes out of scope.
///
/// Not a security guarantee — a `Vec` can be reallocated behind our back
/// and the OS may have paged the old copy out — but it keeps the key from
/// lingering in a freed heap block for the rest of the process's life,
/// which is the case that actually bites.
#[derive(Clone)]
pub struct MasterKey(Vec<u8>);

impl MasterKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        // `write_volatile` through a raw pointer would be stronger, but the
        // crate denies `unsafe`; a plain fill plus a black-box read is what
        // safe Rust can promise.
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey({} bytes, redacted)", self.0.len())
    }
}

/// An unlocked LUKS volume presented as a plaintext [`BlockDevice`].
///
/// Offset 0 of this device is the first byte of the decrypted payload; its
/// [`total_size`](BlockDevice::total_size) is the payload's length, not the
/// underlying container's.
pub struct LuksBackend<B: BlockDevice> {
    inner: B,
    header: Header,
    cipher: SectorCipher,
    /// Byte offset of the payload within `inner`.
    payload_offset: u64,
    /// Payload length in bytes, a whole number of cipher sectors.
    payload_size: u64,
    /// Sector index the IV generator counts from (LUKS2's `iv_tweak`;
    /// always 0 for LUKS1).
    iv_tweak: u64,
    master_key: MasterKey,
    cursor: u64,
    read_only: bool,
}

impl<B: BlockDevice> std::fmt::Debug for LuksBackend<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LuksBackend")
            .field("version", &self.header.version())
            .field("uuid", &self.header.uuid())
            .field("cipher", &self.cipher)
            .field("payload_offset", &self.payload_offset)
            .field("payload_size", &self.payload_size)
            .finish()
    }
}

/// Cap on how much ciphertext one read/write pass buffers, so a
/// whole-device copy doesn't allocate the whole device.
const CHUNK_BYTES: u64 = 1 << 20;

impl<B: BlockDevice> LuksBackend<B> {
    /// Unlock `dev` with `passphrase`, trying every keyslot in turn.
    ///
    /// Returns [`crate::Error::InvalidArgument`] when no slot accepts the
    /// passphrase — the same answer for "wrong passphrase" and "this slot
    /// was never populated", because the two are indistinguishable without
    /// the key.
    pub fn open(dev: B, passphrase: &str) -> Result<Self> {
        Self::open_inner(dev, Some(passphrase.as_bytes()), None, false)
    }

    /// Like [`open`](Self::open) but refuses writes.
    pub fn open_read_only(dev: B, passphrase: &str) -> Result<Self> {
        Self::open_inner(dev, Some(passphrase.as_bytes()), None, true)
    }

    /// Unlock with a master key taken from elsewhere — a key file, a
    /// `cryptsetup luksDump --dump-master-key`, or the caller's own
    /// [`format`] run. The key is still checked against the header's
    /// digest, so a wrong key is rejected rather than silently producing
    /// garbage.
    pub fn open_with_master_key(dev: B, master_key: &[u8]) -> Result<Self> {
        Self::open_inner(dev, None, Some(master_key), false)
    }

    fn open_inner(
        mut dev: B,
        passphrase: Option<&[u8]>,
        master_key: Option<&[u8]>,
        read_only: bool,
    ) -> Result<Self> {
        let mut head = [0u8; 8];
        dev.read_at(0, &mut head)?;
        let (header, mk, payload_offset, payload_size, iv_tweak, cipher_spec, sector_size) =
            match detect(&head) {
                Some(Version::V1) => Self::unlock_v1(&mut dev, passphrase, master_key)?,
                Some(Version::V2) => Self::unlock_v2(&mut dev, passphrase, master_key)?,
                None => {
                    return Err(crate::Error::InvalidImage(
                        "luks: bad magic (not a LUKS volume)".into(),
                    ));
                }
            };

        let cipher = SectorCipher::new(cipher_spec, mk.as_bytes(), sector_size)?;
        Ok(Self {
            inner: dev,
            header,
            cipher,
            payload_offset,
            payload_size,
            iv_tweak,
            master_key: mk,
            cursor: 0,
            read_only,
        })
    }

    #[allow(clippy::type_complexity)]
    fn unlock_v1(
        dev: &mut B,
        passphrase: Option<&[u8]>,
        master_key: Option<&[u8]>,
    ) -> Result<(Header, MasterKey, u64, u64, u64, crypt::CipherSpec, u32)> {
        let mut raw = vec![0u8; v1::PHDR_BYTES];
        dev.read_at(0, &mut raw)?;
        let h = v1::Header::decode(&raw)?;

        let mk = if let Some(key) = master_key {
            if key.len() != h.key_bytes as usize {
                return Err(crate::Error::InvalidArgument(format!(
                    "luks1: master key is {} bytes, the header declares {}",
                    key.len(),
                    h.key_bytes
                )));
            }
            if !h.verify_master_key(key)? {
                return Err(crate::Error::InvalidArgument(
                    "luks1: master key does not match the header digest".into(),
                ));
            }
            MasterKey::new(key.to_vec())
        } else {
            let passphrase = passphrase.expect("open_inner passes one of the two");
            let mut found = None;
            for i in 0..v1::NUM_KEYS {
                if !h.slots[i].is_enabled() {
                    continue;
                }
                let (off, len) = h.slot_material_extent(i);
                let mut material = vec![0u8; len as usize];
                dev.read_at(off, &mut material)?;
                if let Some(mk) = h.unlock_slot(i, passphrase, &mut material)? {
                    found = Some(mk);
                    break;
                }
            }
            MasterKey::new(found.ok_or_else(|| {
                crate::Error::InvalidArgument("luks1: no keyslot accepted the passphrase".into())
            })?)
        };

        let payload_offset = h.payload_offset_bytes();
        let device_size = dev.total_size();
        if payload_offset >= device_size {
            return Err(crate::Error::InvalidImage(format!(
                "luks1: payload starts at {payload_offset} but the device is {device_size} bytes"
            )));
        }
        // A trailing partial sector is not addressable through the cipher.
        let payload_size = (device_size - payload_offset) / 512 * 512;
        let spec = h.cipher_spec()?;
        // LUKS1 always maps the payload with dm-crypt's iv_offset at 0, so
        // the first payload sector is sector 0 for the IV generator.
        Ok((
            Header::V1(Box::new(h)),
            mk,
            payload_offset,
            payload_size,
            0,
            spec,
            512,
        ))
    }

    #[allow(clippy::type_complexity)]
    fn unlock_v2(
        dev: &mut B,
        passphrase: Option<&[u8]>,
        master_key: Option<&[u8]>,
    ) -> Result<(Header, MasterKey, u64, u64, u64, crypt::CipherSpec, u32)> {
        let (bin, meta) = Self::load_v2_metadata(dev)?;
        meta.check_supported()?;

        let (seg_id, seg) = meta.data_segment()?;
        let seg_id = seg_id.to_owned();
        let seg = seg.clone();

        // Try each keyslot; a candidate master key counts only if a digest
        // covering this segment accepts it.
        let mut found: Option<Vec<u8>> = None;
        if let Some(key) = master_key {
            if !Self::v2_digest_accepts(&meta, &seg_id, key)? {
                return Err(crate::Error::InvalidArgument(
                    "luks2: master key does not match any digest for the data segment".into(),
                ));
            }
            found = Some(key.to_vec());
        } else {
            let passphrase = passphrase.expect("open_inner passes one of the two");
            for (id, slot) in &meta.keyslots {
                if slot.kind != "luks2" {
                    continue;
                }
                let (off, len) = slot.material_extent()?;
                let mut material = vec![0u8; len as usize];
                dev.read_at(off, &mut material)?;
                let candidate = match slot.unwrap_master_key(passphrase, &mut material) {
                    Ok(k) => k,
                    // A slot whose KDF or area cipher we can't drive should
                    // not abort the search — another slot may open fine.
                    Err(crate::Error::Unsupported(_)) => continue,
                    Err(e) => return Err(e),
                };
                if Self::v2_slot_digest_accepts(&meta, id, &seg_id, &candidate)? {
                    found = Some(candidate);
                    break;
                }
            }
        }
        let mk = MasterKey::new(found.ok_or_else(|| {
            crate::Error::InvalidArgument("luks2: no keyslot accepted the passphrase".into())
        })?);

        let device_size = dev.total_size();
        if seg.offset >= device_size {
            return Err(crate::Error::InvalidImage(format!(
                "luks2: segment starts at {} but the device is {device_size} bytes",
                seg.offset
            )));
        }
        let avail = device_size - seg.offset;
        let declared = seg.size_bytes()?.unwrap_or(avail);
        if declared > avail {
            return Err(crate::Error::InvalidImage(format!(
                "luks2: segment declares {declared} bytes but only {avail} are on the device"
            )));
        }
        let sector_size = seg.sector_size;
        let payload_size = declared / sector_size as u64 * sector_size as u64;
        let spec = seg.cipher_spec(mk.len())?;
        let iv_tweak = seg.iv_tweak;
        let payload_offset = seg.offset;

        Ok((
            Header::V2 {
                bin: Box::new(bin),
                meta: Box::new(meta),
            },
            mk,
            payload_offset,
            payload_size,
            iv_tweak,
            spec,
            sector_size,
        ))
    }

    /// Load the authoritative LUKS2 header: of the two copies, the one
    /// with the highest `seqid` whose checksum verifies.
    fn load_v2_metadata(dev: &mut B) -> Result<(v2::BinHeader, v2::Metadata)> {
        let mut best: Option<(v2::BinHeader, v2::Metadata)> = None;
        let mut first_error: Option<crate::Error> = None;

        // The primary copy is at 0; the secondary follows it, so its offset
        // is the primary's own hdr_size.
        let mut offsets = vec![0u64];
        let mut primary_head = [0u8; v2::BIN_HDR_BYTES];
        if dev.read_at(0, &mut primary_head).is_ok()
            && let Ok(h) = v2::BinHeader::decode(&primary_head)
        {
            offsets.push(h.hdr_size);
        }

        for off in offsets {
            match Self::load_v2_copy(dev, off) {
                Ok((bin, meta)) => {
                    let better = best.as_ref().is_none_or(|(b, _)| bin.seqid > b.seqid);
                    if better {
                        best = Some((bin, meta));
                    }
                }
                Err(e) => {
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }

        best.ok_or_else(|| {
            first_error.unwrap_or_else(|| {
                crate::Error::InvalidImage("luks2: neither header copy is usable".into())
            })
        })
    }

    fn load_v2_copy(dev: &mut B, offset: u64) -> Result<(v2::BinHeader, v2::Metadata)> {
        let mut head = [0u8; v2::BIN_HDR_BYTES];
        dev.read_at(offset, &mut head)?;
        let bin = v2::BinHeader::decode(&head)?;
        if bin.hdr_offset != offset {
            return Err(crate::Error::InvalidImage(format!(
                "luks2: header copy at {offset} claims to live at {}",
                bin.hdr_offset
            )));
        }
        let mut region = vec![0u8; bin.hdr_size as usize];
        dev.read_at(offset, &mut region)?;
        if !v2::verify_checksum(&bin, &region)? {
            return Err(crate::Error::InvalidImage(format!(
                "luks2: header copy at {offset} fails its {} checksum",
                bin.checksum_alg
            )));
        }
        let meta = v2::Metadata::parse(v2::json_text(&region)?)?;
        Ok((bin, meta))
    }

    /// Does a digest that covers `slot_id` *and* `seg_id` accept `mk`?
    fn v2_slot_digest_accepts(
        meta: &v2::Metadata,
        slot_id: &str,
        seg_id: &str,
        mk: &[u8],
    ) -> Result<bool> {
        for d in meta.digests.values() {
            if !d.keyslots.iter().any(|k| k == slot_id) {
                continue;
            }
            if !d.segments.iter().any(|s| s == seg_id) {
                continue;
            }
            if d.matches(mk)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Does any digest covering `seg_id` accept `mk`? Used on the
    /// master-key path, where there is no keyslot to tie the check to.
    fn v2_digest_accepts(meta: &v2::Metadata, seg_id: &str, mk: &[u8]) -> Result<bool> {
        for d in meta.digests.values() {
            if !d.segments.iter().any(|s| s == seg_id) {
                continue;
            }
            if d.matches(mk)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The decoded header, for diagnostics.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Which LUKS version this volume uses.
    pub fn version(&self) -> Version {
        self.header.version()
    }

    /// The master key. Handle with care — it opens the volume without a
    /// passphrase (see [`open_with_master_key`](Self::open_with_master_key)).
    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    /// Byte offset of the encrypted payload within the container.
    pub fn payload_offset(&self) -> u64 {
        self.payload_offset
    }

    /// The keyed cipher, for diagnostics.
    pub fn cipher(&self) -> &SectorCipher {
        &self.cipher
    }

    /// Consume the backend and hand back the container device.
    pub fn into_inner(self) -> B {
        self.inner
    }

    fn bounds(&self, offset: u64, len: u64) -> Result<u64> {
        let size = self.payload_size;
        let end = offset
            .checked_add(len)
            .ok_or(crate::Error::OutOfBounds { offset, len, size })?;
        if end > size {
            return Err(crate::Error::OutOfBounds { offset, len, size });
        }
        Ok(end)
    }

    /// Decrypt `[offset, offset + buf.len())` of the payload into `buf`.
    fn read_plain(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        self.bounds(offset, buf.len() as u64)?;
        let ss = self.cipher.sector_size() as u64;
        let mut done = 0usize;
        while done < buf.len() {
            let cur = offset + done as u64;
            let sector = cur / ss;
            let skew = cur - sector * ss;
            // Cover the requested bytes with whole sectors, capped so a
            // huge read doesn't allocate a huge scratch buffer.
            let want = (buf.len() - done) as u64;
            let span = (skew + want).min(CHUNK_BYTES.max(ss)).div_ceil(ss) * ss;
            let mut scratch = vec![0u8; span as usize];
            let at = self.payload_offset + sector * ss;
            // The last sector of the payload is a whole sector by
            // construction, so the read never runs past the container.
            self.inner.read_at(at, &mut scratch)?;
            self.cipher.decrypt(self.iv_tweak + sector, &mut scratch)?;
            let take = ((span - skew) as usize).min(buf.len() - done);
            buf[done..done + take].copy_from_slice(&scratch[skew as usize..skew as usize + take]);
            done += take;
        }
        Ok(())
    }

    /// Encrypt `buf` into `[offset, offset + buf.len())` of the payload.
    ///
    /// A write that starts or ends mid-sector reads that sector back
    /// first: the cipher works on whole sectors, so the untouched bytes
    /// have to be re-encrypted alongside the new ones.
    fn write_plain(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        if self.read_only {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "LuksBackend opened read-only — write refused",
            )));
        }
        self.bounds(offset, buf.len() as u64)?;
        let ss = self.cipher.sector_size() as u64;
        let mut done = 0usize;
        while done < buf.len() {
            let cur = offset + done as u64;
            let sector = cur / ss;
            let skew = cur - sector * ss;
            let want = (buf.len() - done) as u64;
            let span = (skew + want).min(CHUNK_BYTES.max(ss)).div_ceil(ss) * ss;
            let take = ((span - skew) as usize).min(buf.len() - done);
            let at = self.payload_offset + sector * ss;

            let mut scratch = vec![0u8; span as usize];
            let partial = skew != 0 || (take as u64) < span;
            if partial {
                // Read-modify-write: pull the covered sectors back as
                // plaintext, splice the new bytes in, re-encrypt.
                self.inner.read_at(at, &mut scratch)?;
                self.cipher.decrypt(self.iv_tweak + sector, &mut scratch)?;
            }
            scratch[skew as usize..skew as usize + take].copy_from_slice(&buf[done..done + take]);
            self.cipher.encrypt(self.iv_tweak + sector, &mut scratch)?;
            self.inner.write_at(at, &scratch)?;
            done += take;
        }
        Ok(())
    }
}

impl<B: BlockDevice> Read for LuksBackend<B> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.payload_size.saturating_sub(self.cursor);
        let n = (buf.len() as u64).min(remaining) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.read_plain(self.cursor, &mut buf[..n])
            .map_err(io::Error::other)?;
        self.cursor += n as u64;
        Ok(n)
    }
}

impl<B: BlockDevice> Write for LuksBackend<B> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = self.payload_size.saturating_sub(self.cursor);
        let n = (buf.len() as u64).min(remaining) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.write_plain(self.cursor, &buf[..n])
            .map_err(io::Error::other)?;
        self.cursor += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<B: BlockDevice> Seek for LuksBackend<B> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::End(n) => self
                .payload_size
                .checked_add_signed(n)
                .ok_or_else(|| io::Error::other("luks: seek past i64 bounds"))?,
            SeekFrom::Current(n) => self
                .cursor
                .checked_add_signed(n)
                .ok_or_else(|| io::Error::other("luks: seek past i64 bounds"))?,
        };
        self.cursor = new;
        Ok(self.cursor)
    }
}

impl<B: BlockDevice> BlockDevice for LuksBackend<B> {
    fn block_size(&self) -> u32 {
        self.cipher.sector_size()
    }

    fn total_size(&self) -> u64 {
        self.payload_size
    }

    fn sync(&mut self) -> Result<()> {
        self.inner.sync()
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_plain(offset, buf)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        self.write_plain(offset, buf)
    }

    fn zero_range(&mut self, offset: u64, len: u64) -> Result<()> {
        // Encrypted zeros are not zeros on disk, so there is no sparse
        // shortcut here: every covered sector must actually be written.
        if len == 0 {
            return Ok(());
        }
        self.bounds(offset, len)?;
        let zero = vec![0u8; CHUNK_BYTES as usize];
        let mut written = 0u64;
        while written < len {
            let n = (len - written).min(CHUNK_BYTES) as usize;
            self.write_plain(offset + written, &zero[..n])?;
            written += n as u64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;

    /// Format a small volume in memory, then reopen it and check the
    /// plaintext survives a round trip.
    fn round_trip(opts: FormatOpts, passphrase: &str) {
        let dev = MemoryBackend::new(8 * 1024 * 1024);
        let mut vol = format(dev, passphrase, &opts).unwrap();

        let payload = vol.total_size();
        assert!(payload > 0);

        let pattern: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        vol.write_at(0, &pattern).unwrap();
        vol.write_at(payload - 512, &pattern[..512]).unwrap();
        // A deliberately unaligned write, to exercise read-modify-write.
        vol.write_at(1234, b"unaligned payload bytes").unwrap();
        vol.sync().unwrap();

        let dev = vol.into_inner();
        let mut vol = LuksBackend::open(dev, passphrase).unwrap();
        assert_eq!(vol.total_size(), payload);

        let mut buf = vec![0u8; 4096];
        vol.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..1234], &pattern[..1234]);
        assert_eq!(&buf[1234..1234 + 23], b"unaligned payload bytes");
        let mut tail = [0u8; 512];
        vol.read_at(payload - 512, &mut tail).unwrap();
        assert_eq!(&tail[..], &pattern[..512]);
    }

    #[test]
    fn luks2_round_trips() {
        round_trip(FormatOpts::fast_for_tests(), "hunter2");
    }

    #[test]
    fn luks1_round_trips() {
        let mut opts = FormatOpts::fast_for_tests();
        opts.version = Version::V1;
        round_trip(opts, "hunter2");
    }

    #[test]
    fn luks1_cbc_essiv_round_trips() {
        let mut opts = FormatOpts::fast_for_tests();
        opts.version = Version::V1;
        opts.cipher = "aes-cbc-essiv:sha256".into();
        opts.key_bytes = 32;
        round_trip(opts, "hunter2");
    }

    #[test]
    fn luks2_4k_sectors_round_trip() {
        let mut opts = FormatOpts::fast_for_tests();
        opts.sector_size = 4096;
        round_trip(opts, "hunter2");
    }

    #[test]
    fn wrong_passphrase_is_refused() {
        for version in [Version::V1, Version::V2] {
            let mut opts = FormatOpts::fast_for_tests();
            opts.version = version;
            let vol = format(MemoryBackend::new(8 * 1024 * 1024), "right", &opts).unwrap();
            let dev = vol.into_inner();
            let err = LuksBackend::open(dev, "wrong").unwrap_err();
            assert!(
                matches!(err, crate::Error::InvalidArgument(_)),
                "{version:?}: {err}"
            );
        }
    }

    #[test]
    fn ciphertext_on_disk_is_not_the_plaintext() {
        let opts = FormatOpts::fast_for_tests();
        let mut vol = format(MemoryBackend::new(8 * 1024 * 1024), "pw", &opts).unwrap();
        let offset = vol.payload_offset();
        vol.write_at(0, &[0xAAu8; 4096]).unwrap();
        let mut dev = vol.into_inner();

        let mut raw = [0u8; 4096];
        dev.read_at(offset, &mut raw).unwrap();
        assert!(
            raw.iter().any(|&b| b != 0xAA),
            "payload stored in the clear"
        );
        // Two identical plaintext sectors must not produce identical
        // ciphertext — that is what the per-sector IV buys.
        assert_ne!(&raw[..512], &raw[512..1024]);
    }

    #[test]
    fn master_key_unlocks_without_the_passphrase() {
        let opts = FormatOpts::fast_for_tests();
        let vol = format(MemoryBackend::new(8 * 1024 * 1024), "pw", &opts).unwrap();
        let mk = vol.master_key().as_bytes().to_vec();
        let dev = vol.into_inner();

        let vol = LuksBackend::open_with_master_key(dev, &mk).unwrap();
        assert_eq!(vol.master_key().as_bytes(), &mk[..]);
        let dev = vol.into_inner();

        let mut wrong = mk.clone();
        wrong[0] ^= 0xff;
        assert!(LuksBackend::open_with_master_key(dev, &wrong).is_err());
    }

    #[test]
    fn probe_recognises_both_versions() {
        for (version, expect) in [(Version::V1, Version::V1), (Version::V2, Version::V2)] {
            let mut opts = FormatOpts::fast_for_tests();
            opts.version = version;
            let vol = format(MemoryBackend::new(8 * 1024 * 1024), "pw", &opts).unwrap();
            let mut dev = vol.into_inner();
            assert_eq!(probe(&mut dev), Some(expect));
        }
        let mut plain = MemoryBackend::new(65536);
        assert_eq!(probe(&mut plain), None);
    }

    #[test]
    fn read_only_refuses_writes() {
        let opts = FormatOpts::fast_for_tests();
        let vol = format(MemoryBackend::new(8 * 1024 * 1024), "pw", &opts).unwrap();
        let dev = vol.into_inner();
        let mut vol = LuksBackend::open_read_only(dev, "pw").unwrap();
        let err = vol.write_at(0, b"nope").unwrap_err();
        assert!(matches!(err, crate::Error::Io(_)));
        // Reads still work.
        let mut buf = [0u8; 512];
        vol.read_at(0, &mut buf).unwrap();
    }

    #[test]
    fn out_of_bounds_is_rejected() {
        let opts = FormatOpts::fast_for_tests();
        let mut vol = format(MemoryBackend::new(8 * 1024 * 1024), "pw", &opts).unwrap();
        let size = vol.total_size();
        let mut buf = [0u8; 16];
        assert!(matches!(
            vol.read_at(size, &mut buf),
            Err(crate::Error::OutOfBounds { .. })
        ));
        assert!(matches!(
            vol.write_at(size - 8, &[0u8; 16]),
            Err(crate::Error::OutOfBounds { .. })
        ));
    }

    /// A large read must be split into bounded chunks and still come back
    /// byte-identical.
    #[test]
    fn multi_chunk_io_round_trips() {
        let opts = FormatOpts::fast_for_tests();
        let mut vol = format(MemoryBackend::new(16 * 1024 * 1024), "pw", &opts).unwrap();
        let len = (3 * CHUNK_BYTES as usize).min(vol.total_size() as usize);
        let data: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(31) % 256) as u8).collect();
        vol.write_at(0, &data).unwrap();
        let mut back = vec![0u8; len];
        vol.read_at(0, &mut back).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn zero_range_clears_the_plaintext() {
        let opts = FormatOpts::fast_for_tests();
        let mut vol = format(MemoryBackend::new(8 * 1024 * 1024), "pw", &opts).unwrap();
        vol.write_at(0, &[0xffu8; 8192]).unwrap();
        vol.zero_range(512, 4096).unwrap();
        let mut buf = [0u8; 8192];
        vol.read_at(0, &mut buf).unwrap();
        assert!(buf[..512].iter().all(|&b| b == 0xff));
        assert!(buf[512..4608].iter().all(|&b| b == 0));
        assert!(buf[4608..].iter().all(|&b| b == 0xff));
    }

    #[test]
    fn version_displays_as_the_format_name() {
        assert_eq!(Version::V1.to_string(), "LUKS1");
        assert_eq!(Version::V2.to_string(), "LUKS2");
    }

    #[test]
    fn master_key_debug_does_not_leak() {
        let k = MasterKey::new(vec![1, 2, 3, 4]);
        assert_eq!(format!("{k:?}"), "MasterKey(4 bytes, redacted)");
    }
}
