//! The I/O traits the block and filesystem layers are written against.
//!
//! With the `std` feature (the default) every item here *is* the
//! corresponding `std::io` item, re-exported: a [`BlockDevice`] is a
//! `std::io::Read + Write + Seek`, a file handle is a `std::io::Read`,
//! and a hosted consumer never sees this module at all.
//!
//! Without `std` the crate is `#![no_std]`, and this module supplies a
//! compact re-implementation of the same surface — the [`Read`],
//! [`Write`] and [`Seek`] traits with their usual provided methods,
//! [`SeekFrom`], [`Error`] / [`ErrorKind`] / [`Result`], [`Cursor`],
//! [`Take`] and [`Empty`] — with the same names and semantics, so the
//! filesystem code compiles unchanged in either configuration and an
//! embedded driver implements the traits it already knows from `std`.
//!
//! [`BlockDevice`]: crate::block::BlockDevice

#[cfg(feature = "std")]
pub use std::io::{
    Cursor, Empty, Error, ErrorKind, Read, Result, Seek, SeekFrom, Take, Write, empty,
};

#[cfg(not(feature = "std"))]
pub use nostd::{
    Cursor, Empty, Error, ErrorKind, Read, Result, Seek, SeekFrom, Take, Write, empty,
};

/// The `no_std` stand-in for `std::io`. Only the surface fstool uses.
#[cfg(not(feature = "std"))]
mod nostd {
    use alloc::boxed::Box;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::fmt;

    /// The category of an I/O error — the subset of `std::io::ErrorKind`
    /// the crate produces or matches on.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum ErrorKind {
        /// An entity was not found.
        NotFound,
        /// The operation lacked the necessary privileges.
        PermissionDenied,
        /// An entity already exists.
        AlreadyExists,
        /// A parameter was incorrect.
        InvalidInput,
        /// Data was not valid for the operation.
        InvalidData,
        /// The stream ended before a `read_exact` was satisfied.
        UnexpectedEof,
        /// A `write` accepted no bytes at all (`write_all` cannot make
        /// progress).
        WriteZero,
        /// The operation is not supported.
        Unsupported,
        /// An allocation failed.
        OutOfMemory,
        /// The operation was interrupted and can be retried.
        Interrupted,
        /// Anything else.
        Other,
    }

    impl ErrorKind {
        fn as_str(self) -> &'static str {
            match self {
                ErrorKind::NotFound => "entity not found",
                ErrorKind::PermissionDenied => "permission denied",
                ErrorKind::AlreadyExists => "entity already exists",
                ErrorKind::InvalidInput => "invalid input parameter",
                ErrorKind::InvalidData => "invalid data",
                ErrorKind::UnexpectedEof => "unexpected end of file",
                ErrorKind::WriteZero => "write zero",
                ErrorKind::Unsupported => "unsupported",
                ErrorKind::OutOfMemory => "out of memory",
                ErrorKind::Interrupted => "operation interrupted",
                ErrorKind::Other => "other error",
            }
        }
    }

    impl fmt::Display for ErrorKind {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.as_str())
        }
    }

    /// An I/O error: a kind plus an optional message.
    #[derive(Debug)]
    pub struct Error {
        kind: ErrorKind,
        msg: Option<String>,
    }

    impl Error {
        /// An error of `kind` carrying `msg`.
        pub fn new<M: fmt::Display>(kind: ErrorKind, msg: M) -> Self {
            Self {
                kind,
                msg: Some(alloc::format!("{msg}")),
            }
        }

        /// An [`ErrorKind::Other`] error carrying `msg`.
        pub fn other<M: fmt::Display>(msg: M) -> Self {
            Self::new(ErrorKind::Other, msg)
        }

        /// The error's category.
        pub fn kind(&self) -> ErrorKind {
            self.kind
        }
    }

    impl From<ErrorKind> for Error {
        fn from(kind: ErrorKind) -> Self {
            Self { kind, msg: None }
        }
    }

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match &self.msg {
                Some(m) => f.write_str(m),
                None => f.write_str(self.kind.as_str()),
            }
        }
    }

    impl core::error::Error for Error {}

    /// `Result` specialised to [`Error`].
    pub type Result<T> = core::result::Result<T, Error>;

    /// A position to seek to, relative to the start, end or current
    /// position of a stream.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum SeekFrom {
        /// Absolute offset from the start.
        Start(u64),
        /// Offset from the end (negative goes backwards).
        End(i64),
        /// Offset from the current position.
        Current(i64),
    }

    /// A source of bytes.
    pub trait Read {
        /// Pull some bytes into `buf`, returning how many were read. `Ok(0)`
        /// means end of stream (or an empty `buf`).
        fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

        /// Fill `buf` completely, or fail with [`ErrorKind::UnexpectedEof`].
        fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
            while !buf.is_empty() {
                match self.read(buf) {
                    Ok(0) => break,
                    Ok(n) => buf = &mut buf[n..],
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            if buf.is_empty() {
                Ok(())
            } else {
                Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ))
            }
        }

        /// Read until end of stream, appending to `buf`; returns the number
        /// of bytes appended.
        fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
            let start = buf.len();
            let mut chunk = [0u8; 4096];
            loop {
                match self.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(buf.len() - start)
        }

        /// Borrow this reader as a `&mut` reader (handy for adapters that
        /// take ownership, like [`take`](Self::take)).
        fn by_ref(&mut self) -> &mut Self
        where
            Self: Sized,
        {
            self
        }

        /// An adapter that reads at most `limit` bytes.
        fn take(self, limit: u64) -> Take<Self>
        where
            Self: Sized,
        {
            Take { inner: self, limit }
        }
    }

    /// A sink for bytes.
    pub trait Write {
        /// Push some bytes from `buf`, returning how many were accepted.
        fn write(&mut self, buf: &[u8]) -> Result<usize>;

        /// Push any buffered bytes through to the destination.
        fn flush(&mut self) -> Result<()>;

        /// Write all of `buf`, or fail with [`ErrorKind::WriteZero`] if the
        /// sink stops accepting bytes.
        fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
            while !buf.is_empty() {
                match self.write(buf) {
                    Ok(0) => {
                        return Err(Error::new(
                            ErrorKind::WriteZero,
                            "failed to write whole buffer",
                        ));
                    }
                    Ok(n) => buf = &buf[n..],
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }

        /// Borrow this writer as a `&mut` writer.
        fn by_ref(&mut self) -> &mut Self
        where
            Self: Sized,
        {
            self
        }
    }

    /// A stream with a movable cursor.
    pub trait Seek {
        /// Move the cursor and return its new absolute position.
        fn seek(&mut self, pos: SeekFrom) -> Result<u64>;

        /// The current absolute position.
        fn stream_position(&mut self) -> Result<u64> {
            self.seek(SeekFrom::Current(0))
        }

        /// Move back to the start.
        fn rewind(&mut self) -> Result<()> {
            self.seek(SeekFrom::Start(0))?;
            Ok(())
        }
    }

    impl<R: Read + ?Sized> Read for &mut R {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            (**self).read(buf)
        }
        fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
            (**self).read_exact(buf)
        }
        fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
            (**self).read_to_end(buf)
        }
    }

    impl<R: Read + ?Sized> Read for Box<R> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            (**self).read(buf)
        }
        fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
            (**self).read_exact(buf)
        }
        fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
            (**self).read_to_end(buf)
        }
    }

    impl Read for &[u8] {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let n = self.len().min(buf.len());
            let (head, tail) = self.split_at(n);
            buf[..n].copy_from_slice(head);
            *self = tail;
            Ok(n)
        }
    }

    impl<W: Write + ?Sized> Write for &mut W {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            (**self).write(buf)
        }
        fn flush(&mut self) -> Result<()> {
            (**self).flush()
        }
        fn write_all(&mut self, buf: &[u8]) -> Result<()> {
            (**self).write_all(buf)
        }
    }

    impl<W: Write + ?Sized> Write for Box<W> {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            (**self).write(buf)
        }
        fn flush(&mut self) -> Result<()> {
            (**self).flush()
        }
        fn write_all(&mut self, buf: &[u8]) -> Result<()> {
            (**self).write_all(buf)
        }
    }

    impl Write for Vec<u8> {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl Write for &mut [u8] {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            let n = self.len().min(buf.len());
            let (head, tail) = core::mem::take(self).split_at_mut(n);
            head.copy_from_slice(&buf[..n]);
            *self = tail;
            Ok(n)
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl<S: Seek + ?Sized> Seek for &mut S {
        fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
            (**self).seek(pos)
        }
    }

    impl<S: Seek + ?Sized> Seek for Box<S> {
        fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
            (**self).seek(pos)
        }
    }

    /// An in-memory stream over anything that dereferences to a byte
    /// slice, with a cursor.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Cursor<T> {
        inner: T,
        pos: u64,
    }

    impl<T> Cursor<T> {
        /// Wrap `inner` with the cursor at 0.
        pub const fn new(inner: T) -> Self {
            Self { inner, pos: 0 }
        }

        /// Unwrap the underlying value.
        pub fn into_inner(self) -> T {
            self.inner
        }

        /// Borrow the underlying value.
        pub const fn get_ref(&self) -> &T {
            &self.inner
        }

        /// Mutably borrow the underlying value.
        pub fn get_mut(&mut self) -> &mut T {
            &mut self.inner
        }

        /// The cursor position.
        pub const fn position(&self) -> u64 {
            self.pos
        }

        /// Move the cursor.
        pub fn set_position(&mut self, pos: u64) {
            self.pos = pos;
        }
    }

    impl<T: AsRef<[u8]>> Read for Cursor<T> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let data = self.inner.as_ref();
            let start = (self.pos as usize).min(data.len());
            let n = (data.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&data[start..start + n]);
            self.pos += n as u64;
            Ok(n)
        }
    }

    impl<T: AsRef<[u8]>> Seek for Cursor<T> {
        fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
            let (base, delta) = match pos {
                SeekFrom::Start(n) => {
                    self.pos = n;
                    return Ok(n);
                }
                SeekFrom::End(d) => (self.inner.as_ref().len() as u64, d),
                SeekFrom::Current(d) => (self.pos, d),
            };
            match base.checked_add_signed(delta) {
                Some(n) => {
                    self.pos = n;
                    Ok(n)
                }
                None => Err(Error::new(
                    ErrorKind::InvalidInput,
                    "invalid seek to a negative or overflowing position",
                )),
            }
        }
    }

    impl Write for Cursor<Vec<u8>> {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            let pos = self.pos as usize;
            let end = pos + buf.len();
            if self.inner.len() < end {
                self.inner.resize(end, 0);
            }
            self.inner[pos..end].copy_from_slice(buf);
            self.pos = end as u64;
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl Write for Cursor<&mut Vec<u8>> {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            let pos = self.pos as usize;
            let end = pos + buf.len();
            if self.inner.len() < end {
                self.inner.resize(end, 0);
            }
            self.inner[pos..end].copy_from_slice(buf);
            self.pos = end as u64;
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl Write for Cursor<&mut [u8]> {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            let pos = (self.pos as usize).min(self.inner.len());
            let n = (self.inner.len() - pos).min(buf.len());
            self.inner[pos..pos + n].copy_from_slice(&buf[..n]);
            self.pos += n as u64;
            Ok(n)
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    /// A reader limited to `limit` bytes (see [`Read::take`]).
    #[derive(Debug)]
    pub struct Take<R> {
        inner: R,
        limit: u64,
    }

    impl<R> Take<R> {
        /// Bytes still allowed through.
        pub const fn limit(&self) -> u64 {
            self.limit
        }

        /// Reset the limit.
        pub fn set_limit(&mut self, limit: u64) {
            self.limit = limit;
        }

        /// Unwrap the underlying reader.
        pub fn into_inner(self) -> R {
            self.inner
        }

        /// Borrow the underlying reader.
        pub const fn get_ref(&self) -> &R {
            &self.inner
        }

        /// Mutably borrow the underlying reader.
        pub fn get_mut(&mut self) -> &mut R {
            &mut self.inner
        }
    }

    impl<R: Read> Read for Take<R> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            if self.limit == 0 {
                return Ok(0);
            }
            let max = (buf.len() as u64).min(self.limit) as usize;
            let n = self.inner.read(&mut buf[..max])?;
            self.limit -= n as u64;
            Ok(n)
        }
    }

    /// A reader that is always at end of stream and a writer that
    /// discards everything (see [`empty`]).
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Empty;

    /// An [`Empty`].
    pub const fn empty() -> Empty {
        Empty
    }

    impl Read for Empty {
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize> {
            Ok(0)
        }
    }

    impl Write for Empty {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl Seek for Empty {
        fn seek(&mut self, _pos: SeekFrom) -> Result<u64> {
            Ok(0)
        }
    }
}
