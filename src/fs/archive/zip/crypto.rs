//! The two zip encryption schemes, as `Read` / `Write` adapters that sit
//! between the device and the method codec.
//!
//! - **Traditional PKWARE** ("ZipCrypto", APPNOTE §6.1): three 32-bit
//!   keys seeded from the passphrase and advanced with every plaintext
//!   byte; a 12-byte header whose last byte is a check value precedes
//!   the body. The scheme is known-plaintext weak and is kept only for
//!   interoperability. No dependencies, always compiled.
//! - **WinZip AES** (method 99, extra field 0x9901, the `zip-aes`
//!   feature): PBKDF2-HMAC-SHA1 with 1000 iterations derives an AES key,
//!   an HMAC-SHA1 key and a 2-byte password verifier from the passphrase
//!   and a per-member salt; the body is AES-CTR with a little-endian
//!   counter starting at 1, followed by the first 10 bytes of the HMAC
//!   over the ciphertext.
//!
//! Both readers verify what the format lets them verify up front — the
//! ZipCrypto check byte, the AES password verifier — so a wrong
//! passphrase is an error on open rather than garbage on read. The AES
//! reader also checks the authentication code when the body has been
//! read to its end.

use std::io::{self, Read, Write};

use crate::{Error, Result};

/// The error a member needing a passphrase reports when none was given.
pub fn needs_password() -> Error {
    Error::InvalidArgument(
        "zip: member is encrypted — pass the passphrase (`--password` / `--password-file`)".into(),
    )
}

/// The error a wrong passphrase reports.
pub fn wrong_password() -> Error {
    Error::InvalidArgument("zip: wrong passphrase for encrypted member".into())
}

/// Random bytes for ZipCrypto headers and AES salts. `uuid`'s v4
/// generator is the one OS-backed randomness source the crate already
/// carries; one call yields 16 bytes.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        out.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    }
    out.truncate(n);
    out
}

// ─── traditional PKWARE ────────────────────────────────────────────────

/// The three-key state machine shared by both directions.
#[derive(Clone)]
pub struct ZipCryptoKeys([u32; 3]);

impl ZipCryptoKeys {
    pub fn new(password: &[u8]) -> Self {
        let mut k = Self([0x1234_5678, 0x2345_6789, 0x3456_7890]);
        for &b in password {
            k.update(b);
        }
        k
    }

    fn update(&mut self, b: u8) {
        self.0[0] = crate::crc::crc32_append(!self.0[0], &[b]) ^ 0xffff_ffff;
        self.0[1] = self.0[1].wrapping_add(self.0[0] & 0xff);
        self.0[1] = self.0[1].wrapping_mul(134_775_813).wrapping_add(1);
        self.0[2] = crate::crc::crc32_append(!self.0[2], &[(self.0[1] >> 24) as u8]) ^ 0xffff_ffff;
    }

    fn stream_byte(&self) -> u8 {
        let t = (self.0[2] | 2) as u16;
        (t.wrapping_mul(t ^ 1) >> 8) as u8
    }

    pub fn decrypt_byte(&mut self, c: u8) -> u8 {
        let p = c ^ self.stream_byte();
        self.update(p);
        p
    }

    pub fn encrypt_byte(&mut self, p: u8) -> u8 {
        let c = p ^ self.stream_byte();
        self.update(p);
        c
    }
}

/// Decrypts a ZipCrypto body. Construction consumes the 12-byte header
/// and verifies its check byte.
pub struct ZipCryptoReader<R: Read> {
    inner: R,
    keys: ZipCryptoKeys,
}

impl<R: Read> ZipCryptoReader<R> {
    pub fn new(mut inner: R, password: &[u8], check: u8) -> Result<Self> {
        let mut keys = ZipCryptoKeys::new(password);
        let mut hdr = [0u8; 12];
        inner.read_exact(&mut hdr).map_err(|_| {
            Error::InvalidImage("zip: encrypted member shorter than its 12-byte header".into())
        })?;
        let mut last = 0;
        for b in hdr {
            last = keys.decrypt_byte(b);
        }
        if last != check {
            return Err(wrong_password());
        }
        Ok(Self { inner, keys })
    }
}

impl<R: Read> Read for ZipCryptoReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        for b in &mut buf[..n] {
            *b = self.keys.decrypt_byte(*b);
        }
        Ok(n)
    }
}

/// Encrypts a ZipCrypto body. Construction writes the 12-byte header:
/// 11 random bytes and the check byte.
pub struct ZipCryptoWriter<W: Write> {
    inner: W,
    keys: ZipCryptoKeys,
}

impl<W: Write> ZipCryptoWriter<W> {
    pub fn new(mut inner: W, password: &[u8], check: u8) -> io::Result<Self> {
        let mut keys = ZipCryptoKeys::new(password);
        let mut hdr = random_bytes(12);
        hdr[11] = check;
        for b in &mut hdr {
            *b = keys.encrypt_byte(*b);
        }
        inner.write_all(&hdr)?;
        Ok(Self { inner, keys })
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for ZipCryptoWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut enc = buf.to_vec();
        for b in &mut enc {
            *b = self.keys.encrypt_byte(*b);
        }
        self.inner.write_all(&enc)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// ─── WinZip AES ────────────────────────────────────────────────────────

/// Salt length for a key size, per the WinZip specification.
pub fn aes_salt_len(key_bits: u16) -> usize {
    key_bits as usize / 16
}

/// Validate an AES strength byte from the 0x9901 extra (1 / 2 / 3).
pub fn aes_key_bits(strength: u8) -> Option<u16> {
    match strength {
        1 => Some(128),
        2 => Some(192),
        3 => Some(256),
        _ => None,
    }
}

#[cfg(feature = "zip-aes")]
mod aes {
    use super::*;
    use purecrypto::cipher::{Aes128, Aes192, Aes256, BlockCipher};
    use purecrypto::hash::{Hmac, Sha1};

    const PBKDF2_ITERATIONS: u32 = 1000;
    const AUTH_LEN: usize = 10;

    enum Cipher {
        A128(Aes128),
        A192(Aes192),
        A256(Aes256),
    }

    impl Cipher {
        fn encrypt_block(&self, block: &mut [u8; 16]) {
            match self {
                Self::A128(c) => c.encrypt_block(block),
                Self::A192(c) => c.encrypt_block(block),
                Self::A256(c) => c.encrypt_block(block),
            }
        }
    }

    /// AES-CTR keystream in WinZip's flavour: the counter is a 128-bit
    /// little-endian integer starting at 1, encrypted in ECB and XORed
    /// into the data. Plus the HMAC-SHA1 over the ciphertext.
    struct Ctr {
        cipher: Cipher,
        counter: u128,
        /// Keystream block for the current counter, and how much of it
        /// has been used — so partial reads keep their position.
        block: [u8; 16],
        used: usize,
        mac: Hmac<Sha1>,
    }

    impl Ctr {
        fn new(password: &[u8], salt: &[u8], key_bits: u16) -> Result<(Self, [u8; 2])> {
            let key_len = key_bits as usize / 8;
            let mut derived = vec![0u8; 2 * key_len + 2];
            purecrypto::kdf::pbkdf2::<Sha1>(password, salt, PBKDF2_ITERATIONS, &mut derived);
            let (enc_key, rest) = derived.split_at(key_len);
            let (mac_key, verifier) = rest.split_at(key_len);
            let cipher = match key_bits {
                128 => Cipher::A128(Aes128::new(enc_key.try_into().unwrap())),
                192 => Cipher::A192(Aes192::new(enc_key.try_into().unwrap())),
                256 => Cipher::A256(Aes256::new(enc_key.try_into().unwrap())),
                _ => {
                    return Err(Error::InvalidImage(format!(
                        "zip: AES member declares a {key_bits}-bit key"
                    )));
                }
            };
            Ok((
                Self {
                    cipher,
                    counter: 1,
                    block: [0u8; 16],
                    used: 16,
                    mac: Hmac::<Sha1>::new(mac_key),
                },
                [verifier[0], verifier[1]],
            ))
        }

        fn xor(&mut self, data: &mut [u8]) {
            for b in data {
                if self.used == 16 {
                    self.block = self.counter.to_le_bytes();
                    self.cipher.encrypt_block(&mut self.block);
                    self.counter = self.counter.wrapping_add(1);
                    self.used = 0;
                }
                *b ^= self.block[self.used];
                self.used += 1;
            }
        }

        fn auth(self) -> [u8; AUTH_LEN] {
            let full = self.mac.finalize();
            let mut out = [0u8; AUTH_LEN];
            out.copy_from_slice(&full[..AUTH_LEN]);
            out
        }
    }

    /// Decrypts a WinZip AES body of `total` bytes (salt + verifier +
    /// data + authentication code). Construction consumes the salt and
    /// verifier and checks the passphrase against the latter; the
    /// authentication code is checked once the data has all been read.
    pub struct AesReader<R: Read> {
        inner: R,
        ctr: Option<Ctr>,
        /// Ciphertext bytes still to deliver.
        remaining: u64,
        verified: bool,
    }

    impl<R: Read> AesReader<R> {
        pub fn new(mut inner: R, password: &[u8], key_bits: u16, total: u64) -> Result<Self> {
            let salt_len = aes_salt_len(key_bits);
            let overhead = (salt_len + 2 + AUTH_LEN) as u64;
            if total < overhead {
                return Err(Error::InvalidImage(
                    "zip: AES member shorter than its salt, verifier and authentication code"
                        .into(),
                ));
            }
            let mut head = vec![0u8; salt_len + 2];
            inner.read_exact(&mut head).map_err(Error::from)?;
            let (ctr, verifier) = Ctr::new(password, &head[..salt_len], key_bits)?;
            if head[salt_len..] != verifier {
                return Err(wrong_password());
            }
            Ok(Self {
                inner,
                ctr: Some(ctr),
                remaining: total - overhead,
                verified: false,
            })
        }
    }

    impl<R: Read> Read for AesReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                if !self.verified {
                    self.verified = true;
                    let mut code = [0u8; AUTH_LEN];
                    self.inner.read_exact(&mut code)?;
                    let ctr = self.ctr.take().expect("ctr present until verified");
                    if ctr.auth() != code {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "zip: AES authentication code mismatch — member is corrupt or tampered",
                        ));
                    }
                }
                return Ok(0);
            }
            let want = (buf.len() as u64).min(self.remaining) as usize;
            let n = self.inner.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "zip: AES member body ended early",
                ));
            }
            let ctr = self.ctr.as_mut().expect("ctr present while data remains");
            ctr.mac.update(&buf[..n]);
            ctr.xor(&mut buf[..n]);
            self.remaining -= n as u64;
            Ok(n)
        }
    }

    /// Encrypts a WinZip AES body. Construction writes the salt and
    /// verifier; [`finish`](Self::finish) appends the authentication
    /// code and hands the sink back.
    pub struct AesWriter<W: Write> {
        inner: W,
        ctr: Option<Ctr>,
    }

    impl<W: Write> AesWriter<W> {
        pub fn new(mut inner: W, password: &[u8], key_bits: u16) -> io::Result<Self> {
            let salt = random_bytes(aes_salt_len(key_bits));
            let (ctr, verifier) = Ctr::new(password, &salt, key_bits).map_err(io::Error::other)?;
            inner.write_all(&salt)?;
            inner.write_all(&verifier)?;
            Ok(Self {
                inner,
                ctr: Some(ctr),
            })
        }

        /// Append the authentication code. Idempotent; writes after it
        /// are refused.
        pub fn finish(&mut self) -> io::Result<()> {
            if let Some(ctr) = self.ctr.take() {
                self.inner.write_all(&ctr.auth())?;
            }
            Ok(())
        }

        pub fn into_inner(self) -> W {
            self.inner
        }
    }

    impl<W: Write> Write for AesWriter<W> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let ctr = self
                .ctr
                .as_mut()
                .ok_or_else(|| io::Error::other("zip: write after AES finish"))?;
            let mut enc = buf.to_vec();
            ctr.xor(&mut enc);
            ctr.mac.update(&enc);
            self.inner.write_all(&enc)?;
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }
}

#[cfg(feature = "zip-aes")]
pub use aes::{AesReader, AesWriter};

/// The error an AES member reports in a build without `zip-aes`.
#[allow(dead_code)]
pub fn aes_disabled() -> Error {
    Error::Unsupported("zip: AES-encrypted member — rebuild with `--features zip-aes`".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zipcrypto_round_trips_and_checks_passphrase() {
        let plain = b"attack at dawn, twelve o'clock sharp".to_vec();
        let mut buf = Vec::new();
        {
            let mut w = ZipCryptoWriter::new(&mut buf, b"pw", 0xab).unwrap();
            w.write_all(&plain).unwrap();
        }
        assert_eq!(buf.len(), plain.len() + 12);
        let mut r = ZipCryptoReader::new(&buf[..], b"pw", 0xab).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
        // The check is one byte, so about one wrong passphrase in 256
        // passes it (the header is random); nearly all must be refused.
        let mut passed = 0;
        for i in 0..1000 {
            match ZipCryptoReader::new(&buf[..], format!("nope{i}").as_bytes(), 0xab) {
                Ok(_) => passed += 1,
                Err(e) => assert!(matches!(e, Error::InvalidArgument(_)), "{e:?}"),
            }
        }
        assert!(passed < 30, "{passed} of 1000 wrong passphrases passed");
    }

    #[cfg(feature = "zip-aes")]
    #[test]
    fn aes_round_trips_and_verifies() {
        for bits in [128u16, 192, 256] {
            let plain = vec![0x5au8; 1000];
            let mut buf = Vec::new();
            let mut w = AesWriter::new(&mut buf, b"secret", bits).unwrap();
            w.write_all(&plain).unwrap();
            w.finish().unwrap();
            assert_eq!(
                buf.len() as u64,
                plain.len() as u64 + (bits as u64 / 16) + 12
            );
            let mut r = AesReader::new(&buf[..], b"secret", bits, buf.len() as u64).unwrap();
            let mut out = Vec::new();
            r.read_to_end(&mut out).unwrap();
            assert_eq!(out, plain);
            // Wrong passphrase fails on the verifier, before any data.
            assert!(AesReader::new(&buf[..], b"wrong", bits, buf.len() as u64).is_err());
            // A flipped ciphertext byte fails the authentication code.
            let mut bad = buf.clone();
            bad[(bits as usize / 16) + 2 + 10] ^= 1;
            let mut r = AesReader::new(&bad[..], b"secret", bits, bad.len() as u64).unwrap();
            assert!(r.read_to_end(&mut Vec::new()).is_err());
        }
    }
}
