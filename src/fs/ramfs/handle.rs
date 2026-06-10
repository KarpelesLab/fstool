//! In-memory read/write file handle for [`super::Ramfs`].
//!
//! Backs [`crate::fs::Filesystem::open_file_rw`] and `open_file_ro`. The
//! handle borrows `&'a mut Ramfs` and indexes straight into the target
//! inode's `Vec<u8>`, so every `write` is "durable" the instant it returns
//! — there is nothing to flush. The `dev` argument of `open_file_rw` is
//! ignored (ramfs has no block device); the handle therefore borrows only
//! the filesystem.

use std::io::{self, Read, Seek, SeekFrom, Write};

use super::Ramfs;
use crate::Result;
use crate::fs::{FileHandle, FileReadHandle};

/// A handle into one ramfs regular file. `Read`/`Write`/`Seek` operate on
/// the inode's byte vector; growth zero-fills, shrink truncates.
pub struct RamFileHandle<'a> {
    fs: &'a mut Ramfs,
    ino: u64,
    pos: u64,
}

impl<'a> RamFileHandle<'a> {
    /// Build a handle positioned at `pos` (0 for read/write, end-of-file for
    /// `O_APPEND`). The caller guarantees `ino` names a regular file.
    pub(super) fn new(fs: &'a mut Ramfs, ino: u64, pos: u64) -> Self {
        Self { fs, ino, pos }
    }

    fn data(&self) -> &[u8] {
        self.fs.file_body(self.ino)
    }

    fn data_mut(&mut self) -> &mut Vec<u8> {
        self.fs.file_body_mut(self.ino)
    }
}

impl Read for RamFileHandle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let data = self.data();
        let len = data.len() as u64;
        if self.pos >= len || buf.is_empty() {
            return Ok(0);
        }
        let start = self.pos as usize;
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for RamFileHandle<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let start = self.pos as usize;
        let end = start + buf.len();
        let data = self.data_mut();
        if data.len() < end {
            // Grow, zero-filling any gap between the old EOF and `start`.
            data.resize(end, 0);
        }
        data[start..end].copy_from_slice(buf);
        self.pos = end as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Writes land in the inode's Vec immediately; nothing to flush.
        Ok(())
    }
}

impl Seek for RamFileHandle<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let len = self.data().len() as i128;
        let new_pos: i128 = match pos {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(d) => len + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ramfs: seek to negative offset",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

impl FileHandle for RamFileHandle<'_> {
    fn len(&self) -> u64 {
        self.data().len() as u64
    }

    fn set_len(&mut self, new_len: u64) -> Result<()> {
        let new_len = new_len as usize;
        self.data_mut().resize(new_len, 0);
        if self.pos > new_len as u64 {
            self.pos = new_len as u64;
        }
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        Ok(())
    }
}

impl FileReadHandle for RamFileHandle<'_> {
    fn len(&self) -> u64 {
        self.data().len() as u64
    }
}
