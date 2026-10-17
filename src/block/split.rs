//! A device concatenated from several files — the volumes of a split
//! archive (`foo.z01`, `foo.z02`, …, `foo.zip`, or 7-Zip's
//! `foo.zip.001`, `foo.zip.002`, …) read as one contiguous byte range.
//!
//! The volumes are exposed through [`BlockDevice::segments`] so a format
//! whose offsets are relative to a volume (zip's "disk number start")
//! can translate them; a format that simply spans the boundary (7-Zip's
//! byte-split sets) needs no translation and sees one flat device.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::{BlockDevice, FileBackend};
use crate::Result;

/// Several devices glued end to end.
pub struct SplitBackend {
    parts: Vec<Box<dyn BlockDevice>>,
    /// Start offset of each part in the concatenation; `starts[0] == 0`.
    starts: Vec<u64>,
    total: u64,
    /// Stream position for the `Read` / `Write` / `Seek` view.
    cursor: u64,
}

impl SplitBackend {
    /// Concatenate `parts` in order. At least one part is required.
    pub fn new(parts: Vec<Box<dyn BlockDevice>>) -> Result<Self> {
        if parts.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "split: a volume set needs at least one volume".into(),
            ));
        }
        let mut starts = Vec::with_capacity(parts.len());
        let mut total = 0u64;
        for p in &parts {
            starts.push(total);
            total = total.checked_add(p.total_size()).ok_or_else(|| {
                crate::Error::InvalidArgument("split: volume set too large".into())
            })?;
        }
        Ok(Self {
            parts,
            starts,
            total,
            cursor: 0,
        })
    }

    /// The volume files that make up the set `path` belongs to, in
    /// archive order, or `None` when `path` is not part of a recognised
    /// set. Two conventions are understood:
    ///
    /// - Info-ZIP / PKZIP: `name.z01`, `name.z02`, … then `name.zip`
    ///   last. `path` may name the `.zip` or any `.zNN`.
    /// - Numbered byte splits (7-Zip `-v`, `split -d`): `name.001`,
    ///   `name.002`, …, given any one of them.
    ///
    /// Only an unbroken run of volumes is accepted: a set whose second
    /// volume is missing is reported as an error rather than silently
    /// read short.
    pub fn volume_set(path: &Path) -> Result<Option<Vec<PathBuf>>> {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return Ok(None);
        };
        let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        let lower = name.to_ascii_lowercase();

        // Info-ZIP: `.zip` with a `.z01` sibling, or a `.zNN` itself.
        let stem = if lower.ends_with(".zip") {
            Some(&name[..name.len() - 4])
        } else {
            // `.z01` … `.z99`, `.z100` …: `.z` followed by two or more digits.
            let rest = lower.trim_end_matches(|c: char| c.is_ascii_digit());
            let digits = name.len() - rest.len();
            if rest.ends_with(".z") && digits >= 2 {
                Some(&name[..rest.len() - 2])
            } else {
                None
            }
        };
        if let Some(stem) = stem {
            let last = dir.join(format!("{stem}.zip"));
            let z = |n: usize| dir.join(format!("{stem}.z{n:02}"));
            if z(1).exists() {
                let mut vols = Vec::new();
                let mut n = 1;
                while z(n).exists() {
                    vols.push(z(n));
                    n += 1;
                }
                if !last.exists() {
                    return Err(crate::Error::InvalidArgument(format!(
                        "{}: split archive is missing its final volume {}",
                        path.display(),
                        last.display()
                    )));
                }
                vols.push(last);
                return Ok(Some(vols));
            }
            if !lower.ends_with(".zip") {
                // Named a `.zNN` but no `.z01`: not a set we can read.
                return Err(crate::Error::InvalidArgument(format!(
                    "{}: split archive is missing its first volume {}",
                    path.display(),
                    z(1).display()
                )));
            }
            return Ok(None);
        }

        // Numbered byte splits: `name.NNN`, all digits, at least 3.
        if let Some(dot) = name.rfind('.') {
            let (base, ext) = (&name[..dot], &name[dot + 1..]);
            if ext.len() >= 3 && ext.bytes().all(|b| b.is_ascii_digit()) && !base.is_empty() {
                let width = ext.len();
                let part = |n: usize| dir.join(format!("{base}.{n:0width$}"));
                if !part(1).exists() {
                    return Ok(None);
                }
                let mut vols = Vec::new();
                let mut n = 1;
                while part(n).exists() {
                    vols.push(part(n));
                    n += 1;
                }
                return Ok(Some(vols));
            }
        }
        Ok(None)
    }

    /// Open `path`'s volume set as one device, or `None` when `path` is
    /// a plain single file. `read_only` opens every volume `O_RDONLY`.
    pub fn open_volume_set(path: &Path, read_only: bool) -> Result<Option<Self>> {
        let Some(vols) = Self::volume_set(path)? else {
            return Ok(None);
        };
        let mut parts: Vec<Box<dyn BlockDevice>> = Vec::with_capacity(vols.len());
        for v in &vols {
            let f = if read_only {
                FileBackend::open_read_only(v)?
            } else {
                FileBackend::open(v)?
            };
            parts.push(Box::new(f));
        }
        Self::new(parts).map(Some)
    }

    /// Number of volumes.
    pub fn volumes(&self) -> usize {
        self.parts.len()
    }

    /// Index of the part holding `offset`, and the offset within it.
    fn locate(&self, offset: u64) -> (usize, u64) {
        let i = match self.starts.binary_search(&offset) {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        (i, offset - self.starts[i])
    }

    fn check(&self, offset: u64, len: usize) -> Result<()> {
        if offset.saturating_add(len as u64) > self.total {
            return Err(crate::Error::OutOfBounds {
                offset,
                len: len as u64,
                size: self.total,
            });
        }
        Ok(())
    }
}

impl Read for SplitBackend {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.cursor >= self.total {
            return Ok(0);
        }
        let n = ((self.total - self.cursor).min(out.len() as u64)) as usize;
        self.read_at(self.cursor, &mut out[..n])
            .map_err(io::Error::other)?;
        self.cursor += n as u64;
        Ok(n)
    }
}

impl Write for SplitBackend {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.cursor >= self.total {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "split: write past the end of the volume set",
            ));
        }
        let n = ((self.total - self.cursor).min(data.len() as u64)) as usize;
        self.write_at(self.cursor, &data[..n])
            .map_err(io::Error::other)?;
        self.cursor += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for SplitBackend {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(d) => self.total as i128 + d as i128,
            SeekFrom::Current(d) => self.cursor as i128 + d as i128,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.cursor = new as u64;
        Ok(self.cursor)
    }
}

impl BlockDevice for SplitBackend {
    fn block_size(&self) -> u32 {
        self.parts[0].block_size()
    }

    fn total_size(&self) -> u64 {
        self.total
    }

    fn sync(&mut self) -> Result<()> {
        for p in &mut self.parts {
            p.sync()?;
        }
        Ok(())
    }

    fn read_at(&mut self, mut offset: u64, mut buf: &mut [u8]) -> Result<()> {
        self.check(offset, buf.len())?;
        while !buf.is_empty() {
            let (i, within) = self.locate(offset);
            let room = (self.parts[i].total_size() - within).min(buf.len() as u64) as usize;
            let (head, tail) = buf.split_at_mut(room);
            self.parts[i].read_at(within, head)?;
            buf = tail;
            offset += room as u64;
        }
        Ok(())
    }

    fn write_at(&mut self, mut offset: u64, mut buf: &[u8]) -> Result<()> {
        self.check(offset, buf.len())?;
        while !buf.is_empty() {
            let (i, within) = self.locate(offset);
            let room = (self.parts[i].total_size() - within).min(buf.len() as u64) as usize;
            let (head, tail) = buf.split_at(room);
            self.parts[i].write_at(within, head)?;
            buf = tail;
            offset += room as u64;
        }
        Ok(())
    }

    fn segments(&self) -> Option<&[u64]> {
        Some(&self.starts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;

    fn mem(bytes: &[u8]) -> Box<dyn BlockDevice> {
        let mut m = MemoryBackend::new(bytes.len() as u64);
        m.write_at(0, bytes).unwrap();
        Box::new(m)
    }

    #[test]
    fn reads_and_writes_across_boundaries() {
        let mut dev = SplitBackend::new(vec![mem(b"abcd"), mem(b"efg"), mem(b"hij")]).unwrap();
        assert_eq!(dev.total_size(), 10);
        assert_eq!(dev.segments(), Some(&[0u64, 4, 7][..]));
        let mut out = [0u8; 10];
        dev.read_at(0, &mut out).unwrap();
        assert_eq!(&out, b"abcdefghij");
        let mut mid = [0u8; 5];
        dev.read_at(3, &mut mid).unwrap();
        assert_eq!(&mid, b"defgh");
        dev.write_at(2, b"XYZW").unwrap();
        dev.read_at(0, &mut out).unwrap();
        assert_eq!(&out, b"abXYZWghij");
        assert!(dev.read_at(8, &mut [0u8; 3]).is_err());
    }

    #[test]
    fn recognises_volume_sets() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        // Not a set: a lone .zip.
        std::fs::write(d.join("lone.zip"), b"x").unwrap();
        assert_eq!(SplitBackend::volume_set(&d.join("lone.zip")).unwrap(), None);
        // Info-ZIP set, named by the .zip or by a .zNN.
        for n in ["set.z01", "set.z02", "set.zip"] {
            std::fs::write(d.join(n), b"x").unwrap();
        }
        let want = vec![d.join("set.z01"), d.join("set.z02"), d.join("set.zip")];
        assert_eq!(
            SplitBackend::volume_set(&d.join("set.zip")).unwrap(),
            Some(want.clone())
        );
        assert_eq!(
            SplitBackend::volume_set(&d.join("set.z02")).unwrap(),
            Some(want)
        );
        // Missing final volume is an error, not a short read.
        std::fs::write(d.join("broken.z01"), b"x").unwrap();
        assert!(SplitBackend::volume_set(&d.join("broken.z01")).is_err());
        // Numbered byte split.
        for n in ["big.zip.001", "big.zip.002"] {
            std::fs::write(d.join(n), b"x").unwrap();
        }
        assert_eq!(
            SplitBackend::volume_set(&d.join("big.zip.002")).unwrap(),
            Some(vec![d.join("big.zip.001"), d.join("big.zip.002")])
        );
        assert_eq!(SplitBackend::volume_set(&d.join("v1.2.3")).unwrap(), None);
    }
}
