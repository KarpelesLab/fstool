//! [`Volume`] for [`fat::Volume`](crate::fs::fat::Volume).

use super::{
    Entry, ErrorKind, FsType, Kind, Metadata, Volume, VolumeDirIter, VolumeError, VolumeFile,
};
use crate::device::SectorDriver;
use crate::fs::fat::{Dir, DirIter, Error, File, Volume as Fat};

impl<E> VolumeError for Error<E> {
    fn kind(&self) -> ErrorKind {
        match self {
            Error::Io(_) => ErrorKind::Io,
            Error::NotFat => ErrorKind::NotRecognised,
            Error::SectorSizeMismatch { .. }
            | Error::ScratchTooSmall { .. }
            | Error::VolumeExceedsDevice
            | Error::NoSuchPartition => ErrorKind::Geometry,
            Error::NotFound => ErrorKind::NotFound,
            Error::NotADirectory => ErrorKind::NotADirectory,
            Error::IsADirectory => ErrorKind::IsADirectory,
            Error::AlreadyExists => ErrorKind::AlreadyExists,
            Error::DirectoryNotEmpty => ErrorKind::DirectoryNotEmpty,
            Error::InvalidName => ErrorKind::InvalidName,
            Error::InvalidPath => ErrorKind::InvalidPath,
            Error::DirectoryFull => ErrorKind::DirectoryFull,
            Error::NoSpace => ErrorKind::NoSpace,
            Error::CorruptChain => ErrorKind::Corrupt,
            Error::FileTooLarge => ErrorKind::FileTooLarge,
            Error::InvalidOffset => ErrorKind::InvalidOffset,
            Error::Unsupported(_) => ErrorKind::Unsupported,
        }
    }
}

impl<D: SectorDriver, const S: usize> Volume for Fat<D, S> {
    type Error = Error<D::Error>;
    type Device = D;
    type File = File;
    type Dir = Dir;
    type DirIter<'a>
        = FatDirIter<'a, D, S>
    where
        Self: 'a;

    fn fs_type(&self) -> FsType {
        FsType::Fat
    }
    fn root(&self) -> Dir {
        Fat::root(self)
    }
    fn open_dir(&mut self, path: &str) -> Result<Dir, Self::Error> {
        Fat::open_dir(self, path)
    }
    fn iter_dir(&mut self, dir: Dir) -> Self::DirIter<'_> {
        let mut it = Fat::iter_dir(self, dir);
        it.skip_dots = true;
        FatDirIter(it)
    }
    fn metadata(&mut self, path: &str) -> Result<Metadata, Self::Error> {
        Fat::metadata(self, path).map(|m| meta(m.is_dir(), m.len() as u64))
    }
    fn exists(&mut self, path: &str) -> Result<bool, Self::Error> {
        Fat::exists(self, path)
    }
    fn create_dir(&mut self, path: &str) -> Result<Dir, Self::Error> {
        Fat::create_dir(self, path)
    }
    fn remove_dir(&mut self, path: &str) -> Result<(), Self::Error> {
        Fat::remove_dir(self, path)
    }
    fn remove_file(&mut self, path: &str) -> Result<(), Self::Error> {
        Fat::remove_file(self, path)
    }
    fn open_file(&mut self, path: &str) -> Result<File, Self::Error> {
        Fat::open_file(self, path)
    }
    fn create_file(&mut self, path: &str) -> Result<File, Self::Error> {
        Fat::create_file(self, path)
    }
    fn open_or_create_file(&mut self, path: &str) -> Result<File, Self::Error> {
        Fat::open_or_create_file(self, path)
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        Fat::flush(self)
    }
    fn total_bytes(&self) -> u64 {
        Fat::total_bytes(self)
    }
    fn free_bytes(&mut self) -> Result<u64, Self::Error> {
        Fat::free_bytes(self)
    }
    fn unmount(self) -> Result<D, Self::Error> {
        Fat::unmount(self)
    }
}

/// FAT offsets are 32-bit; anything past that is out of the file's reach.
fn narrow<E>(v: u64, err: Error<E>) -> Result<u32, Error<E>> {
    u32::try_from(v).map_err(|_| err)
}

impl<D: SectorDriver, const S: usize> VolumeFile<Fat<D, S>> for File {
    fn len(&self) -> u64 {
        File::len(self) as u64
    }
    fn pos(&self) -> u64 {
        File::pos(self) as u64
    }
    fn seek(&mut self, vol: &mut Fat<D, S>, pos: u64) -> Result<(), Error<D::Error>> {
        File::seek(self, vol, narrow(pos, Error::InvalidOffset)?)
    }
    fn read(&mut self, vol: &mut Fat<D, S>, buf: &mut [u8]) -> Result<usize, Error<D::Error>> {
        File::read(self, vol, buf)
    }
    fn read_exact(&mut self, vol: &mut Fat<D, S>, buf: &mut [u8]) -> Result<(), Error<D::Error>> {
        File::read_exact(self, vol, buf)
    }
    fn write(&mut self, vol: &mut Fat<D, S>, buf: &[u8]) -> Result<usize, Error<D::Error>> {
        File::write(self, vol, buf)
    }
    fn write_all(&mut self, vol: &mut Fat<D, S>, buf: &[u8]) -> Result<(), Error<D::Error>> {
        File::write_all(self, vol, buf)
    }
    fn set_len(&mut self, vol: &mut Fat<D, S>, len: u64) -> Result<(), Error<D::Error>> {
        File::set_len(self, vol, narrow(len, Error::FileTooLarge)?)
    }
    fn flush(&mut self, vol: &mut Fat<D, S>) -> Result<(), Error<D::Error>> {
        File::flush(self, vol)
    }
}

/// A FAT listing, without `.` and `..`.
pub struct FatDirIter<'a, D: SectorDriver, const S: usize>(DirIter<'a, D, S>);

impl<D: SectorDriver, const S: usize> VolumeDirIter for FatDirIter<'_, D, S> {
    type Error = Error<D::Error>;

    fn next(&mut self) -> Result<Option<Entry<'_>>, Self::Error> {
        Ok(self
            .0
            .next()?
            .map(|e| Entry::new(e.name().as_bytes(), meta(e.is_dir(), e.len() as u64))))
    }
}

pub(super) fn meta(dir: bool, len: u64) -> Metadata {
    Metadata::new(if dir { Kind::Dir } else { Kind::File }, len)
}
