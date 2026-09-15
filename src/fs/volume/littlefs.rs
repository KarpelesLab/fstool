//! [`Volume`] for [`littlefs::Volume`](crate::fs::littlefs::Volume), on any
//! [`FlashDriver`] — raw flash, or a card through
//! [`SectorFlash`](crate::device::SectorFlash).

use super::{
    Entry, ErrorKind, FsType, Kind, Metadata, Volume, VolumeDirIter, VolumeError, VolumeFile,
};
use crate::device::FlashDriver;
use crate::fs::littlefs::{Dir, DirIter, Error, File, Volume as LittleFs};

impl<E> VolumeError for Error<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            Error::Io(_) => ErrorKind::Io,
            Error::NotLittleFs => ErrorKind::NotRecognised,
            Error::UnsupportedVersion { .. } | Error::Unsupported(_) => ErrorKind::Unsupported,
            Error::GeometryMismatch { .. } | Error::BadGeometry | Error::ScratchTooSmall { .. } => {
                ErrorKind::Geometry
            }
            Error::Corrupt(_) => ErrorKind::Corrupt,
            Error::NotFound => ErrorKind::NotFound,
            Error::NotADirectory => ErrorKind::NotADirectory,
            Error::IsADirectory => ErrorKind::IsADirectory,
            Error::AlreadyExists => ErrorKind::AlreadyExists,
            Error::DirectoryNotEmpty => ErrorKind::DirectoryNotEmpty,
            Error::InvalidName | Error::AttrTooLarge => ErrorKind::InvalidName,
            Error::InvalidPath => ErrorKind::InvalidPath,
            Error::NoSpace => ErrorKind::NoSpace,
            Error::CommitTooLarge => ErrorKind::DirectoryFull,
            Error::FileTooLarge => ErrorKind::FileTooLarge,
            Error::InvalidOffset => ErrorKind::InvalidOffset,
        }
    }
}

fn meta(dir: bool, len: u32) -> Metadata {
    Metadata::new(if dir { Kind::Dir } else { Kind::File }, len as u64)
}

impl<D: FlashDriver, const B: usize, const P: usize> Volume for LittleFs<D, B, P> {
    type Error = Error<D::Error>;
    type Device = D;
    type File = File;
    type Dir = Dir;
    type DirIter<'a>
        = LittleFsDirIter<'a, D, B, P>
    where
        Self: 'a;

    fn fs_type(&self) -> FsType {
        FsType::LittleFs
    }
    fn root(&self) -> Dir {
        LittleFs::root(self)
    }
    fn open_dir(&mut self, path: &str) -> Result<Dir, Self::Error> {
        LittleFs::open_dir(self, path)
    }
    fn iter_dir(&mut self, dir: Dir) -> Self::DirIter<'_> {
        LittleFsDirIter(LittleFs::iter_dir(self, dir))
    }
    fn metadata(&mut self, path: &str) -> Result<Metadata, Self::Error> {
        LittleFs::metadata(self, path).map(|m| meta(m.is_dir(), m.len()))
    }
    fn exists(&mut self, path: &str) -> Result<bool, Self::Error> {
        LittleFs::exists(self, path)
    }
    fn create_dir(&mut self, path: &str) -> Result<Dir, Self::Error> {
        LittleFs::create_dir(self, path)
    }
    fn remove_dir(&mut self, path: &str) -> Result<(), Self::Error> {
        LittleFs::remove_dir(self, path)
    }
    fn remove_file(&mut self, path: &str) -> Result<(), Self::Error> {
        LittleFs::remove_file(self, path)
    }
    fn open_file(&mut self, path: &str) -> Result<File, Self::Error> {
        LittleFs::open_file(self, path)
    }
    fn create_file(&mut self, path: &str) -> Result<File, Self::Error> {
        LittleFs::create_file(self, path)
    }
    fn open_or_create_file(&mut self, path: &str) -> Result<File, Self::Error> {
        LittleFs::open_or_create_file(self, path)
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        LittleFs::sync(self)
    }
    fn total_bytes(&self) -> u64 {
        let g = self.geometry();
        g.block_count as u64 * g.block_size as u64
    }
    fn free_bytes(&mut self) -> Result<u64, Self::Error> {
        let bs = self.geometry().block_size as u64;
        Ok(LittleFs::free_blocks(self)? as u64 * bs)
    }
    fn statfs(&mut self) -> Result<crate::fs::StatFs, Self::Error> {
        LittleFs::statfs(self)
    }
    fn unmount(self) -> Result<D, Self::Error> {
        LittleFs::unmount(self)
    }
}

impl<D: FlashDriver, const B: usize, const P: usize> VolumeFile<LittleFs<D, B, P>> for File {
    fn len(&self) -> u64 {
        File::len(self) as u64
    }
    fn pos(&self) -> u64 {
        File::pos(self) as u64
    }
    fn seek(&mut self, _vol: &mut LittleFs<D, B, P>, pos: u64) -> Result<(), Error<D::Error>> {
        File::seek(self, u32::try_from(pos).map_err(|_| Error::InvalidOffset)?);
        Ok(())
    }
    fn read(
        &mut self,
        vol: &mut LittleFs<D, B, P>,
        buf: &mut [u8],
    ) -> Result<usize, Error<D::Error>> {
        File::read(self, vol, buf)
    }
    fn read_exact(
        &mut self,
        vol: &mut LittleFs<D, B, P>,
        buf: &mut [u8],
    ) -> Result<(), Error<D::Error>> {
        File::read_exact(self, vol, buf)
    }
    fn write(&mut self, vol: &mut LittleFs<D, B, P>, buf: &[u8]) -> Result<usize, Error<D::Error>> {
        File::write(self, vol, buf)
    }
    fn write_all(
        &mut self,
        vol: &mut LittleFs<D, B, P>,
        buf: &[u8],
    ) -> Result<(), Error<D::Error>> {
        File::write_all(self, vol, buf)
    }
    fn set_len(&mut self, vol: &mut LittleFs<D, B, P>, len: u64) -> Result<(), Error<D::Error>> {
        File::set_len(
            self,
            vol,
            u32::try_from(len).map_err(|_| Error::FileTooLarge)?,
        )
    }
    fn flush(&mut self, vol: &mut LittleFs<D, B, P>) -> Result<(), Error<D::Error>> {
        File::sync(self, vol)
    }
}

/// A littlefs listing.
pub struct LittleFsDirIter<'a, D: FlashDriver, const B: usize, const P: usize>(
    DirIter<'a, D, B, P>,
);

impl<D: FlashDriver, const B: usize, const P: usize> VolumeDirIter
    for LittleFsDirIter<'_, D, B, P>
{
    type Error = Error<D::Error>;

    fn next(&mut self) -> Result<Option<Entry<'_>>, Self::Error> {
        Ok(self
            .0
            .next()?
            .map(|e| Entry::new(e.name(), meta(e.is_dir(), e.len()))))
    }
}
