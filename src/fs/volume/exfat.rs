//! [`Volume`] for [`exfat::Volume`](crate::fs::exfat::Volume).

use super::fat::meta;
use super::{Entry, ErrorKind, FsType, Metadata, Volume, VolumeDirIter, VolumeError, VolumeFile};
use crate::device::SectorDriver;
use crate::fs::exfat::{Dir, DirIter, Error, File, Volume as Exfat};

impl<E> VolumeError for Error<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            Error::Io(_) => ErrorKind::Io,
            Error::NotExfat => ErrorKind::NotRecognised,
            Error::UnsupportedVersion { .. } | Error::Unsupported(_) => ErrorKind::Unsupported,
            Error::SectorSizeMismatch { .. }
            | Error::ScratchTooSmall { .. }
            | Error::VolumeExceedsDevice
            | Error::NoSuchPartition => ErrorKind::Geometry,
            Error::BadGeometry | Error::CorruptChain | Error::CorruptEntry => ErrorKind::Corrupt,
            Error::NoAllocationBitmap => ErrorKind::ReadOnly,
            Error::NotFound => ErrorKind::NotFound,
            Error::NotADirectory => ErrorKind::NotADirectory,
            Error::IsADirectory => ErrorKind::IsADirectory,
            Error::AlreadyExists => ErrorKind::AlreadyExists,
            Error::DirectoryNotEmpty => ErrorKind::DirectoryNotEmpty,
            Error::InvalidName => ErrorKind::InvalidName,
            Error::InvalidPath => ErrorKind::InvalidPath,
            Error::DirectoryFull => ErrorKind::DirectoryFull,
            Error::NoSpace => ErrorKind::NoSpace,
            Error::FileTooLarge => ErrorKind::FileTooLarge,
            Error::InvalidOffset => ErrorKind::InvalidOffset,
        }
    }
}

impl<D: SectorDriver, const S: usize> Volume for Exfat<D, S> {
    type Error = Error<D::Error>;
    type Device = D;
    type File = File;
    type Dir = Dir;
    type DirIter<'a>
        = ExfatDirIter<'a, D, S>
    where
        Self: 'a;

    fn fs_type(&self) -> FsType {
        FsType::Exfat
    }
    fn root(&self) -> Dir {
        Exfat::root(self)
    }
    fn open_dir(&mut self, path: &str) -> Result<Dir, Self::Error> {
        Exfat::open_dir(self, path)
    }
    fn iter_dir(&mut self, dir: Dir) -> Self::DirIter<'_> {
        ExfatDirIter(Exfat::iter_dir(self, dir))
    }
    fn metadata(&mut self, path: &str) -> Result<Metadata, Self::Error> {
        Exfat::metadata(self, path).map(|m| meta(m.is_dir(), m.len()))
    }
    fn exists(&mut self, path: &str) -> Result<bool, Self::Error> {
        Exfat::exists(self, path)
    }
    fn create_dir(&mut self, path: &str) -> Result<Dir, Self::Error> {
        Exfat::create_dir(self, path)
    }
    fn remove_dir(&mut self, path: &str) -> Result<(), Self::Error> {
        Exfat::remove_dir(self, path)
    }
    fn remove_file(&mut self, path: &str) -> Result<(), Self::Error> {
        Exfat::remove_file(self, path)
    }
    fn open_file(&mut self, path: &str) -> Result<File, Self::Error> {
        Exfat::open_file(self, path)
    }
    fn create_file(&mut self, path: &str) -> Result<File, Self::Error> {
        Exfat::create_file(self, path)
    }
    fn open_or_create_file(&mut self, path: &str) -> Result<File, Self::Error> {
        Exfat::open_or_create_file(self, path)
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        Exfat::flush(self)
    }
    fn total_bytes(&self) -> u64 {
        Exfat::total_bytes(self)
    }
    fn free_bytes(&mut self) -> Result<u64, Self::Error> {
        Exfat::free_bytes(self)
    }
    fn statfs(&mut self) -> Result<crate::fs::StatFs, Self::Error> {
        Exfat::statfs(self)
    }
    fn unmount(self) -> Result<D, Self::Error> {
        Exfat::unmount(self)
    }
}

impl<D: SectorDriver, const S: usize> VolumeFile<Exfat<D, S>> for File {
    fn len(&self) -> u64 {
        File::len(self)
    }
    fn pos(&self) -> u64 {
        File::pos(self)
    }
    fn seek(&mut self, _vol: &mut Exfat<D, S>, pos: u64) -> Result<(), Error<D::Error>> {
        File::seek(self, pos);
        Ok(())
    }
    fn read(&mut self, vol: &mut Exfat<D, S>, buf: &mut [u8]) -> Result<usize, Error<D::Error>> {
        File::read(self, vol, buf)
    }
    fn read_exact(&mut self, vol: &mut Exfat<D, S>, buf: &mut [u8]) -> Result<(), Error<D::Error>> {
        File::read_exact(self, vol, buf)
    }
    fn write(&mut self, vol: &mut Exfat<D, S>, buf: &[u8]) -> Result<usize, Error<D::Error>> {
        File::write(self, vol, buf)
    }
    fn write_all(&mut self, vol: &mut Exfat<D, S>, buf: &[u8]) -> Result<(), Error<D::Error>> {
        File::write_all(self, vol, buf)
    }
    fn set_len(&mut self, vol: &mut Exfat<D, S>, len: u64) -> Result<(), Error<D::Error>> {
        File::set_len(self, vol, len)
    }
    fn flush(&mut self, vol: &mut Exfat<D, S>) -> Result<(), Error<D::Error>> {
        File::flush(self, vol)
    }
}

/// An exFAT listing.
pub struct ExfatDirIter<'a, D: SectorDriver, const S: usize>(DirIter<'a, D, S>);

impl<D: SectorDriver, const S: usize> VolumeDirIter for ExfatDirIter<'_, D, S> {
    type Error = Error<D::Error>;

    fn next(&mut self) -> Result<Option<Entry<'_>>, Self::Error> {
        Ok(self
            .0
            .next()?
            .map(|e| Entry::new(e.name().as_bytes(), meta(e.is_dir(), e.len()))))
    }
}
