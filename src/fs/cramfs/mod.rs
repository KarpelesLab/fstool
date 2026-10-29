//! cramfs — the Linux compressed ROM filesystem.
//!
//! A small, read-only format from the late 1990s that still turns up in
//! router and set-top-box firmware. Reads and writes (build-once, like
//! SquashFS: `create` / `repack` lay the whole image out at `flush`).
//!
//! ## Layout
//!
//! - A 76-byte superblock at offset 0, or at 512 when the image was padded
//!   for a boot sector. It ends with the root's inode.
//! - Directory data: each directory is one contiguous run of its children's
//!   inodes, each a 12-byte header followed by the name, NUL-padded to a
//!   multiple of four. All directory data comes before all file data.
//! - File data: per file, a table of `u32` block pointers (the absolute
//!   end offset of each compressed block), then the zlib-compressed blocks.
//!   A block whose start equals its end is a hole and reads as zeros.
//!   Symlinks store their target the same way.
//! - Devices keep their (old-style 8:8) device number in the size field.
//!
//! An inode packs mode (16 bits), uid (16), size (24), gid (8), name
//! length in 4-byte units (6) and data offset in 4-byte units (26), so a
//! file tops out at 16 MiB, names at 252 bytes, and every directory and
//! file must start within the first 256 MiB of the image.
//!
//! Images are in the byte order of the machine that built them. Both
//! orders read; the writer emits little-endian.
//!
//! ## Reference
//!
//! - `include/uapi/linux/cramfs_fs.h` and `fs/cramfs/inode.c` in Linux.
//! - `disk-utils/mkfs.cramfs.c` / `fsck.cramfs.c` in util-linux.

use std::io::{Read, Seek, SeekFrom};

use crate::Result;
use crate::block::BlockDevice;
use crate::compression::Algo;
use crate::fs::{DirEntry, EntryKind};

mod writer;

/// Magic number, in the byte order of the image.
const CRAMFS_MAGIC: u32 = 0x28CD_3D45;
/// Signature string at offset 16 of the superblock.
const CRAMFS_SIGNATURE: &[u8; 16] = b"Compressed ROMFS";
/// Size of the superblock, root inode included.
const SUPER_SIZE: u64 = 76;
/// Size of an inode header, name excluded.
const INODE_SIZE: u64 = 12;

/// `fsid` carries the image size, block and file counts and a CRC.
const FLAG_FSID_VERSION_2: u32 = 0x0000_0001;
/// Directory entries are sorted by name.
const FLAG_SORTED_DIRS: u32 = 0x0000_0002;
/// Zero-length blocks are holes.
const FLAG_HOLES: u32 = 0x0000_0100;
/// Reserved; set by some old tools.
const FLAG_WRONG_SIGNATURE: u32 = 0x0000_0200;
/// The root may live somewhere other than right after the superblock.
const FLAG_SHIFTED_ROOT_OFFSET: u32 = 0x0000_0400;
/// Block pointers carry the uncompressed / direct-pointer flags below.
const FLAG_EXT_BLOCK_POINTERS: u32 = 0x0000_0800;
/// Every flag the kernel accepts: the low byte is reserved for compatible
/// features.
const SUPPORTED_FLAGS: u32 = 0x0000_00FF
    | FLAG_HOLES
    | FLAG_WRONG_SIGNATURE
    | FLAG_SHIFTED_ROOT_OFFSET
    | FLAG_EXT_BLOCK_POINTERS;

/// Block pointer flag: the block is stored raw.
const BLK_FLAG_UNCOMPRESSED: u32 = 1 << 31;
/// Block pointer flag: the pointer is the block's start (>> 2), not the
/// previous block's end.
const BLK_FLAG_DIRECT_PTR: u32 = 1 << 30;
const BLK_FLAGS: u32 = BLK_FLAG_UNCOMPRESSED | BLK_FLAG_DIRECT_PTR;

/// Largest file size the 24-bit size field holds.
const MAX_FILE_SIZE: u64 = (1 << 24) - 1;
/// Longest name the 6-bit length field (in 4-byte units) holds.
const MAX_NAME_LEN: usize = 63 * 4;
/// Highest byte offset the 26-bit offset field (in 4-byte units) reaches.
const MAX_OFFSET: u64 = (1 << 26) << 2;
/// Longest symlink target we read back.
const MAX_SYMLINK: u64 = 64 * 1024;
/// Block sizes tried when guessing the size an image was built with.
const BLOCK_SIZE_CANDIDATES: [u32; 5] = [4096, 8192, 16384, 32768, 65536];
/// Default block size: the page size of nearly every kernel that runs cramfs.
pub const DEFAULT_BLOCK_SIZE: u32 = 4096;

/// Byte order of an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        match self {
            Self::Little => u32::from_le_bytes(a),
            Self::Big => u32::from_be_bytes(a),
        }
    }

    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        match self {
            Self::Little => u16::from_le_bytes(a),
            Self::Big => u16::from_be_bytes(a),
        }
    }
}

/// One on-disk inode, unpacked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawInode {
    /// Full `st_mode`, type bits included.
    mode: u16,
    uid: u16,
    /// File size, directory data size, or device number.
    size: u32,
    gid: u8,
    /// Name length in 4-byte units.
    namelen: u8,
    /// Data offset in 4-byte units; 0 when there is no data.
    offset: u32,
}

impl RawInode {
    /// Unpack the three words. C bitfields fill from the low bits on a
    /// little-endian machine and from the high bits on a big-endian one.
    fn decode(b: &[u8], e: Endian) -> Self {
        let (w0, w1, w2) = (e.u32(&b[0..4]), e.u32(&b[4..8]), e.u32(&b[8..12]));
        match e {
            Endian::Little => Self {
                mode: w0 as u16,
                uid: (w0 >> 16) as u16,
                size: w1 & 0x00FF_FFFF,
                gid: (w1 >> 24) as u8,
                namelen: (w2 & 0x3F) as u8,
                offset: w2 >> 6,
            },
            Endian::Big => Self {
                mode: (w0 >> 16) as u16,
                uid: w0 as u16,
                size: w1 >> 8,
                gid: w1 as u8,
                namelen: (w2 >> 26) as u8,
                offset: w2 & 0x03FF_FFFF,
            },
        }
    }

    /// Pack as little-endian (the only order the writer emits).
    fn encode_le(&self) -> [u8; 12] {
        let w0 = u32::from(self.mode) | (u32::from(self.uid) << 16);
        let w1 = (self.size & 0x00FF_FFFF) | (u32::from(self.gid) << 24);
        let w2 = u32::from(self.namelen & 0x3F) | (self.offset << 6);
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&w0.to_le_bytes());
        out[4..8].copy_from_slice(&w1.to_le_bytes());
        out[8..12].copy_from_slice(&w2.to_le_bytes());
        out
    }

    fn data_offset(&self) -> u64 {
        u64::from(self.offset) << 2
    }

    fn kind(&self) -> EntryKind {
        kind_from_mode(self.mode)
    }
}

fn kind_from_mode(mode: u16) -> EntryKind {
    match u32::from(mode) & 0o170000 {
        0o040000 => EntryKind::Dir,
        0o100000 => EntryKind::Regular,
        0o120000 => EntryKind::Symlink,
        0o020000 => EntryKind::Char,
        0o060000 => EntryKind::Block,
        0o010000 => EntryKind::Fifo,
        0o140000 => EntryKind::Socket,
        _ => EntryKind::Unknown,
    }
}

/// The superblock, minus the root inode (kept separately).
#[derive(Debug, Clone)]
pub struct Superblock {
    /// Image length in bytes (version-2 images; 0 otherwise).
    pub size: u32,
    /// Feature flags.
    pub flags: u32,
    /// `fsid.crc` — CRC-32 of the image with this field zeroed.
    pub crc: u32,
    /// `fsid.edition`.
    pub edition: u32,
    /// `fsid.blocks` — data blocks across all files.
    pub blocks: u32,
    /// `fsid.files` — inode count, root included.
    pub files: u32,
    /// Volume name, NULs stripped.
    pub name: Vec<u8>,
}

/// Quick detection: the magic (either byte order) plus the signature, at
/// offset 0 or 512.
pub fn probe(dev: &mut dyn BlockDevice) -> Result<bool> {
    Ok(find_super(dev)?.is_some())
}

/// Locate the superblock: `(base, endian)` where `base` is its offset.
fn find_super(dev: &mut dyn BlockDevice) -> Result<Option<(u64, Endian)>> {
    for base in [0u64, 512] {
        if dev.total_size() < base + SUPER_SIZE {
            continue;
        }
        let mut head = [0u8; 32];
        dev.read_at(base, &mut head)?;
        if &head[16..32] != CRAMFS_SIGNATURE {
            continue;
        }
        let m = [head[0], head[1], head[2], head[3]];
        if u32::from_le_bytes(m) == CRAMFS_MAGIC {
            return Ok(Some((base, Endian::Little)));
        }
        if u32::from_be_bytes(m) == CRAMFS_MAGIC {
            return Ok(Some((base, Endian::Big)));
        }
    }
    Ok(None)
}

/// Format-time options for [`Cramfs::format`].
#[derive(Debug, Clone)]
pub struct FormatOpts {
    /// Data block size — the page size of the kernel that will mount the
    /// image. A power of two between 4 KiB and 64 KiB; 4 KiB by default.
    pub block_size: u32,
    /// Volume name stored in the superblock (at most 16 bytes).
    pub name: String,
    /// `fsid.edition` value.
    pub edition: u32,
}

impl Default for FormatOpts {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            name: "Compressed".into(),
            edition: 0,
        }
    }
}

impl FormatOpts {
    /// Apply a generic option bag (CLI `-O key=val` / TOML
    /// `[filesystem.options]`): `block_size`, `name`, `edition`. Unknown
    /// keys stay in the map for the caller to flag.
    pub fn apply_options(&mut self, map: &mut crate::format_opts::OptionMap) -> Result<()> {
        if let Some(sz) = map.take_size("block_size")? {
            self.block_size = u32::try_from(sz).map_err(|_| {
                crate::Error::InvalidArgument(format!("cramfs: block_size {sz} too large"))
            })?;
        }
        if let Some(name) = map.take_str("name") {
            self.name = name;
        }
        if let Some(ed) = map.take_u32("edition")? {
            self.edition = ed;
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if !self.block_size.is_power_of_two() || !(4096..=65536).contains(&self.block_size) {
            return Err(crate::Error::InvalidArgument(format!(
                "cramfs: block_size {} must be a power of two between 4 KiB and 64 KiB",
                self.block_size
            )));
        }
        if self.name.len() > 16 {
            return Err(crate::Error::InvalidArgument(format!(
                "cramfs: volume name {:?} is longer than 16 bytes",
                self.name
            )));
        }
        Ok(())
    }
}

/// A resolved path: the inode and where its 12-byte header sits.
#[derive(Debug, Clone, Copy)]
struct Located {
    inode: RawInode,
    /// Image offset of the inode header.
    pos: u64,
}

impl Located {
    /// A stable inode number. Anything with data is numbered by its data
    /// offset (as the kernel does, so hard links share a number); anything
    /// without by its own header position, made odd so it can never meet a
    /// data offset, which is always a multiple of four.
    fn ino(&self) -> u32 {
        if self.inode.offset != 0 {
            (self.inode.data_offset()) as u32
        } else {
            (self.pos as u32) | 1
        }
    }
}

/// Open handle on a cramfs image. After [`Cramfs::format`] it is in write
/// mode until [`Cramfs::flush`] lays the image out; then it reads.
pub struct Cramfs {
    sb: Superblock,
    endian: Endian,
    /// Offset of the superblock (0, or 512 for a padded image).
    base: u64,
    root: RawInode,
    block_size: u32,
    /// Bytes of the device that belong to the image.
    image_size: u64,
    write_state: Option<writer::WriteState>,
}

impl std::fmt::Debug for Cramfs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cramfs")
            .field("sb", &self.sb)
            .field("endian", &self.endian)
            .field("block_size", &self.block_size)
            .field("write_mode", &self.write_state.is_some())
            .finish()
    }
}

impl Cramfs {
    /// Open an existing image. Validates the superblock and works out the
    /// block size it was built with.
    pub fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        let (base, endian) = find_super(dev)?.ok_or_else(|| {
            crate::Error::InvalidImage("cramfs: no superblock (magic/signature mismatch)".into())
        })?;
        let mut buf = [0u8; SUPER_SIZE as usize];
        dev.read_at(base, &mut buf)?;
        let flags = endian.u32(&buf[8..12]);
        if flags & !SUPPORTED_FLAGS != 0 {
            return Err(crate::Error::Unsupported(format!(
                "cramfs: unsupported feature flags {:#x}",
                flags & !SUPPORTED_FLAGS
            )));
        }
        let name_raw = &buf[48..64];
        let name_len = name_raw.iter().position(|&b| b == 0).unwrap_or(16);
        let sb = Superblock {
            size: endian.u32(&buf[4..8]),
            flags,
            crc: endian.u32(&buf[32..36]),
            edition: endian.u32(&buf[36..40]),
            blocks: endian.u32(&buf[40..44]),
            files: endian.u32(&buf[44..48]),
            name: name_raw[..name_len].to_vec(),
        };
        let root = RawInode::decode(&buf[64..76], endian);
        if kind_from_mode(root.mode) != EntryKind::Dir {
            return Err(crate::Error::InvalidImage(
                "cramfs: root inode is not a directory".into(),
            ));
        }
        let dev_size = dev.total_size();
        let image_size = if flags & FLAG_FSID_VERSION_2 != 0 {
            let s = u64::from(sb.size);
            if s > dev_size {
                return Err(crate::Error::InvalidImage(format!(
                    "cramfs: superblock claims {s} bytes but the device holds {dev_size}"
                )));
            }
            s
        } else {
            dev_size
        };
        let root_off = root.data_offset();
        if root_off != 0
            && flags & FLAG_SHIFTED_ROOT_OFFSET == 0
            && root_off != SUPER_SIZE
            && root_off != 512 + SUPER_SIZE
        {
            return Err(crate::Error::InvalidImage(format!(
                "cramfs: bad root offset {root_off}"
            )));
        }
        let mut fs = Self {
            sb,
            endian,
            base,
            root,
            block_size: DEFAULT_BLOCK_SIZE,
            image_size,
            write_state: None,
        };
        fs.block_size = fs.detect_block_size(dev)?;
        Ok(fs)
    }

    /// Begin building a fresh image on `dev`. Populate it with the
    /// `create_*` calls, then [`flush`](Self::flush) to lay it out.
    pub fn format(_dev: &mut dyn BlockDevice, opts: &FormatOpts) -> Result<Self> {
        opts.validate()?;
        Ok(Self {
            sb: Superblock {
                size: 0,
                flags: 0,
                crc: 0,
                edition: opts.edition,
                blocks: 0,
                files: 0,
                name: opts.name.as_bytes().to_vec(),
            },
            endian: Endian::Little,
            base: 0,
            root: RawInode {
                mode: 0o040755,
                uid: 0,
                size: 0,
                gid: 0,
                namelen: 0,
                offset: 0,
            },
            block_size: opts.block_size,
            image_size: 0,
            write_state: Some(writer::WriteState::new(opts)),
        })
    }

    /// Lay every buffered entry out on the device and switch to read mode.
    /// A no-op on an image that was opened rather than formatted.
    pub fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        let Some(state) = self.write_state.take() else {
            return Ok(());
        };
        state.flush(dev)?;
        *self = Self::open(dev)?;
        Ok(())
    }

    /// The superblock.
    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    /// Image length in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.image_size
    }

    /// Data block size the image was built with.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Volume name from the superblock.
    pub fn volume_name(&self) -> String {
        String::from_utf8_lossy(&self.sb.name).into_owned()
    }

    /// `fsid.files` — inode count, root included (0 on version-1 images).
    pub fn file_count(&self) -> u32 {
        self.sb.files
    }

    /// `fsid.edition`.
    pub fn edition(&self) -> u32 {
        self.sb.edition
    }

    /// True when the image is big-endian (built on a big-endian host).
    pub fn big_endian(&self) -> bool {
        self.endian == Endian::Big
    }

    fn check_read_mode(&self) -> Result<()> {
        if self.write_state.is_some() {
            return Err(crate::Error::InvalidArgument(
                "cramfs: image is being built; reads are available after flush()".into(),
            ));
        }
        Ok(())
    }

    fn root_located(&self) -> Located {
        Located {
            inode: self.root,
            pos: self.base + SUPER_SIZE - INODE_SIZE,
        }
    }

    /// Read a directory's children, in on-disk order.
    fn read_dir(
        &self,
        dev: &mut dyn BlockDevice,
        dir: &RawInode,
    ) -> Result<Vec<(Vec<u8>, Located)>> {
        let start = dir.data_offset();
        let len = u64::from(dir.size);
        if len == 0 {
            return Ok(Vec::new());
        }
        let end = start
            .checked_add(len)
            .filter(|&e| start != 0 && e <= self.image_size)
            .ok_or_else(|| {
                crate::Error::InvalidImage(format!(
                    "cramfs: directory data {start}+{len} runs past the image"
                ))
            })?;
        let mut buf = vec![0u8; len as usize];
        dev.read_at(start, &mut buf)?;
        let mut out = Vec::new();
        let mut at = 0usize;
        while at < buf.len() {
            if buf.len() - at < INODE_SIZE as usize {
                return Err(crate::Error::InvalidImage(
                    "cramfs: truncated directory entry".into(),
                ));
            }
            let inode = RawInode::decode(&buf[at..at + 12], self.endian);
            let nl = usize::from(inode.namelen) * 4;
            let name_start = at + 12;
            if nl == 0 || name_start + nl > buf.len() {
                return Err(crate::Error::InvalidImage(format!(
                    "cramfs: bad name length in directory at {start}"
                )));
            }
            let raw = &buf[name_start..name_start + nl];
            let n = raw.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
            if n == 0 {
                return Err(crate::Error::InvalidImage(
                    "cramfs: empty name in directory".into(),
                ));
            }
            out.push((
                raw[..n].to_vec(),
                Located {
                    inode,
                    pos: start + at as u64,
                },
            ));
            at = name_start + nl;
        }
        debug_assert_eq!(start + at as u64, end);
        Ok(out)
    }

    /// Resolve an absolute path. `/`, `""` and `.` are the root.
    fn resolve(&self, dev: &mut dyn BlockDevice, path: &str) -> Result<Located> {
        self.check_read_mode()?;
        let mut cur = self.root_located();
        for comp in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            if cur.inode.kind() != EntryKind::Dir {
                return Err(crate::Error::InvalidArgument(format!(
                    "cramfs: {path:?}: not a directory"
                )));
            }
            let children = self.read_dir(dev, &cur.inode)?;
            cur = children
                .into_iter()
                .find(|(n, _)| n.as_slice() == comp.as_bytes())
                .map(|(_, l)| l)
                .ok_or_else(|| {
                    crate::Error::InvalidArgument(format!("cramfs: no such entry: {path:?}"))
                })?;
        }
        Ok(cur)
    }

    /// List a directory by absolute path.
    pub fn list_path(&self, dev: &mut dyn BlockDevice, path: &str) -> Result<Vec<DirEntry>> {
        let dir = self.resolve(dev, path)?;
        if dir.inode.kind() != EntryKind::Dir {
            return Err(crate::Error::InvalidArgument(format!(
                "cramfs: {path:?} is not a directory"
            )));
        }
        Ok(self
            .read_dir(dev, &dir.inode)?
            .into_iter()
            .map(|(name, l)| {
                let kind = l.inode.kind();
                DirEntry {
                    name: String::from_utf8_lossy(&name).into_owned(),
                    inode: l.ino(),
                    kind,
                    size: if kind == EntryKind::Regular {
                        u64::from(l.inode.size)
                    } else {
                        0
                    },
                }
            })
            .collect())
    }

    fn data_reader<'a>(
        &self,
        dev: &'a mut dyn BlockDevice,
        inode: &RawInode,
    ) -> Result<FileReader<'a>> {
        FileReader::new(
            dev,
            inode,
            self.block_size,
            self.endian,
            self.sb.flags & FLAG_EXT_BLOCK_POINTERS != 0,
            self.image_size,
        )
    }

    /// Open a regular file for random-access reads.
    pub fn open_file_read_handle<'a>(
        &self,
        dev: &'a mut dyn BlockDevice,
        path: &str,
    ) -> Result<FileReader<'a>> {
        let l = self.resolve(dev, path)?;
        if l.inode.kind() != EntryKind::Regular {
            return Err(crate::Error::InvalidArgument(format!(
                "cramfs: {path:?} is not a regular file"
            )));
        }
        self.data_reader(dev, &l.inode)
    }

    /// Open a streaming reader on the regular file at `path`.
    pub fn open_file_reader<'a>(
        &self,
        dev: &'a mut dyn BlockDevice,
        path: &str,
    ) -> Result<Box<dyn Read + 'a>> {
        Ok(Box::new(self.open_file_read_handle(dev, path)?))
    }

    /// Read a symlink's target.
    pub fn read_symlink(&self, dev: &mut dyn BlockDevice, path: &str) -> Result<String> {
        let l = self.resolve(dev, path)?;
        if l.inode.kind() != EntryKind::Symlink {
            return Err(crate::Error::InvalidArgument(format!(
                "cramfs: {path:?} is not a symlink"
            )));
        }
        if u64::from(l.inode.size) > MAX_SYMLINK {
            return Err(crate::Error::InvalidImage(format!(
                "cramfs: symlink {path:?} is {} bytes long",
                l.inode.size
            )));
        }
        let mut r = self.data_reader(dev, &l.inode)?;
        let mut out = Vec::with_capacity(l.inode.size as usize);
        r.read_to_end(&mut out)?;
        String::from_utf8(out).map_err(|_| {
            crate::Error::InvalidImage(format!("cramfs: symlink {path:?} target is not UTF-8"))
        })
    }

    /// Full attributes for `path`. cramfs keeps no timestamps, so all
    /// three times read as 0 (the epoch), as on a mounted image.
    pub fn attrs(&self, dev: &mut dyn BlockDevice, path: &str) -> Result<crate::fs::FileAttrs> {
        let l = self.resolve(dev, path)?;
        let kind = l.inode.kind();
        let (size, rdev) = match kind {
            EntryKind::Char | EntryKind::Block => (0, l.inode.size),
            EntryKind::Fifo | EntryKind::Socket => (0, 0),
            _ => (u64::from(l.inode.size), 0),
        };
        Ok(crate::fs::FileAttrs {
            kind,
            mode: l.inode.mode & 0o7777,
            uid: u32::from(l.inode.uid),
            gid: u32::from(l.inode.gid),
            size,
            blocks: size.div_ceil(512),
            nlink: if kind == EntryKind::Dir { 2 } else { 1 },
            atime: 0,
            mtime: 0,
            ctime: 0,
            rdev,
            inode: l.ino(),
        })
    }

    /// The block size isn't recorded anywhere: it is the page size of the
    /// machine that built the image. Every multi-block-capable file rules
    /// out the sizes its block pointer table contradicts; the smallest size
    /// left standing wins. Files that fit one block at several sizes read
    /// the same under any of them, so the choice among those is harmless.
    /// Defaults to 4 KiB.
    fn detect_block_size(&self, dev: &mut dyn BlockDevice) -> Result<u32> {
        if self.sb.flags & FLAG_EXT_BLOCK_POINTERS != 0 {
            return Ok(DEFAULT_BLOCK_SIZE);
        }
        let mut alive = BLOCK_SIZE_CANDIDATES.to_vec();
        let mut queue = vec![self.root];
        let mut seen = 0usize;
        'walk: while let Some(dir) = queue.pop() {
            let Ok(children) = self.read_dir(dev, &dir) else {
                continue;
            };
            for (_, l) in children {
                seen += 1;
                if seen > 512 || alive.len() <= 1 {
                    break 'walk;
                }
                match l.inode.kind() {
                    EntryKind::Dir => queue.push(l.inode),
                    EntryKind::Regular if l.inode.size > DEFAULT_BLOCK_SIZE => {
                        let mut keep = Vec::with_capacity(alive.len());
                        for &bs in &alive {
                            if self.table_consistent(dev, &l.inode, bs)? {
                                keep.push(bs);
                            }
                        }
                        // A corrupt file shouldn't wipe out every candidate.
                        if !keep.is_empty() {
                            alive = keep;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(alive.first().copied().unwrap_or(DEFAULT_BLOCK_SIZE))
    }

    /// Whether `inode`'s block pointers make sense for block size `bs`:
    /// non-decreasing ends inside the image, the first block starting right
    /// after the table, every non-hole block opening with a zlib header, and
    /// the first such block inflating to the length `bs` implies.
    fn table_consistent(
        &self,
        dev: &mut dyn BlockDevice,
        inode: &RawInode,
        bs: u32,
    ) -> Result<bool> {
        let size = u64::from(inode.size);
        let n = size.div_ceil(u64::from(bs));
        let off = inode.data_offset();
        let table_end = off + n * 4;
        if table_end > self.image_size {
            return Ok(false);
        }
        let mut table = vec![0u8; (n * 4) as usize];
        dev.read_at(off, &mut table)?;
        let mut start = table_end;
        let mut inflated_one = false;
        for i in 0..n {
            let iu = i as usize;
            let end = u64::from(self.endian.u32(&table[iu * 4..iu * 4 + 4]));
            if end < start || end > self.image_size {
                return Ok(false);
            }
            if end > start {
                let mut hdr = [0u8; 2];
                dev.read_at(start, &mut hdr)?;
                // zlib: CM = 8, and the header is a multiple of 31.
                if hdr[0] & 0x0F != 8 || (u16::from(hdr[0]) << 8 | u16::from(hdr[1])) % 31 != 0 {
                    return Ok(false);
                }
                if !inflated_one && end - start <= 2 * u64::from(bs) + 64 {
                    inflated_one = true;
                    let mut raw = vec![0u8; (end - start) as usize];
                    dev.read_at(start, &mut raw)?;
                    let want = (size - i * u64::from(bs)).min(u64::from(bs)) as usize;
                    match crate::compression::decompress(Algo::Zlib, &raw, 65536) {
                        Ok(out) if out.len() == want => {}
                        _ => return Ok(false),
                    }
                }
            }
            start = end;
        }
        Ok(true)
    }
}

/// `Read + Seek` over one file's (or symlink's) data, decoding a block at
/// a time and caching the last one.
pub struct FileReader<'a> {
    dev: &'a mut dyn BlockDevice,
    /// Image offset of the block pointer table.
    table: u64,
    size: u64,
    nblocks: u64,
    block_size: u32,
    endian: Endian,
    ext_ptrs: bool,
    image_size: u64,
    pos: u64,
    cached: Option<(u64, Vec<u8>)>,
}

impl<'a> FileReader<'a> {
    fn new(
        dev: &'a mut dyn BlockDevice,
        inode: &RawInode,
        block_size: u32,
        endian: Endian,
        ext_ptrs: bool,
        image_size: u64,
    ) -> Result<Self> {
        let size = u64::from(inode.size);
        let nblocks = size.div_ceil(u64::from(block_size));
        let table = inode.data_offset();
        if size > 0 && (table == 0 || table + nblocks * 4 > image_size) {
            return Err(crate::Error::InvalidImage(format!(
                "cramfs: block table at {table} runs past the image"
            )));
        }
        Ok(Self {
            dev,
            table,
            size,
            nblocks,
            block_size,
            endian,
            ext_ptrs,
            image_size,
            pos: 0,
            cached: None,
        })
    }

    fn read_u32(&mut self, at: u64) -> Result<u32> {
        let mut b = [0u8; 4];
        self.dev.read_at(at, &mut b)?;
        Ok(self.endian.u32(&b))
    }

    fn read_u16(&mut self, at: u64) -> Result<u16> {
        let mut b = [0u8; 2];
        self.dev.read_at(at, &mut b)?;
        Ok(self.endian.u16(&b))
    }

    /// Where block `idx` lives: `(start, len, uncompressed)`. Mirrors the
    /// kernel's `cramfs_read_folio`, direct pointers included.
    fn locate(&mut self, idx: u64) -> Result<(u64, u64, bool)> {
        let bs = u64::from(self.block_size);
        let mut ptr = self.read_u32(self.table + idx * 4)?;
        let (mut uncompressed, mut direct) = (false, false);
        if self.ext_ptrs {
            uncompressed = ptr & BLK_FLAG_UNCOMPRESSED != 0;
            direct = ptr & BLK_FLAG_DIRECT_PTR != 0;
            ptr &= !BLK_FLAGS;
        }
        if direct {
            let start = u64::from(ptr) << 2;
            if uncompressed {
                let len = (self.size - idx * bs).min(bs);
                Ok((start, len, true))
            } else {
                let len = u64::from(self.read_u16(start)?);
                Ok((start + 2, len, false))
            }
        } else {
            let mut start = self.table + self.nblocks * 4;
            if idx > 0 {
                let prev = self.read_u32(self.table + (idx - 1) * 4)?;
                if self.ext_ptrs && prev & BLK_FLAG_DIRECT_PTR != 0 {
                    let pstart = u64::from(prev & !BLK_FLAGS) << 2;
                    start = if prev & BLK_FLAG_UNCOMPRESSED != 0 {
                        pstart + bs
                    } else {
                        pstart + 2 + u64::from(self.read_u16(pstart)?)
                    };
                } else {
                    start = u64::from(if self.ext_ptrs {
                        prev & !BLK_FLAGS
                    } else {
                        prev
                    });
                }
            }
            let end = u64::from(ptr);
            if end < start {
                return Err(crate::Error::InvalidImage(format!(
                    "cramfs: block {idx} ends ({end}) before it starts ({start})"
                )));
            }
            Ok((start, end - start, uncompressed))
        }
    }

    /// Decode block `idx` into exactly the bytes it should hold.
    fn load(&mut self, idx: u64) -> Result<Vec<u8>> {
        let bs = u64::from(self.block_size);
        let want = (self.size - idx * bs).min(bs) as usize;
        let (start, len, uncompressed) = self.locate(idx)?;
        if len == 0 {
            return Ok(vec![0u8; want]);
        }
        if start + len > self.image_size || len > 2 * bs + 64 {
            return Err(crate::Error::InvalidImage(format!(
                "cramfs: block {idx} at {start}+{len} is out of range"
            )));
        }
        let mut raw = vec![0u8; len as usize];
        self.dev.read_at(start, &mut raw)?;
        let mut out = if uncompressed {
            raw
        } else {
            crate::compression::decompress(Algo::Zlib, &raw, bs as usize)?
        };
        if out.len() != want {
            return Err(crate::Error::InvalidImage(format!(
                "cramfs: block {idx} decoded to {} bytes, expected {want}",
                out.len()
            )));
        }
        out.truncate(want);
        Ok(out)
    }
}

impl Read for FileReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let bs = u64::from(self.block_size);
        let idx = self.pos / bs;
        if self.cached.as_ref().is_none_or(|(i, _)| *i != idx) {
            let data = self.load(idx).map_err(std::io::Error::other)?;
            self.cached = Some((idx, data));
        }
        let (_, data) = self.cached.as_ref().expect("cached above");
        let within = (self.pos - idx * bs) as usize;
        let n = (data.len() - within).min(buf.len());
        buf[..n].copy_from_slice(&data[within..within + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for FileReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.size.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        }
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek before start")
        })?;
        self.pos = new;
        Ok(new)
    }
}

impl crate::fs::FileReadHandle for FileReader<'_> {
    fn len(&self) -> u64 {
        self.size
    }
}

// ----------------------------------------------------------------------
// Trait impls. cramfs is build-once: the `create_*` calls only work
// between `format()` and `flush()`, and nothing can be removed.
// ----------------------------------------------------------------------

fn path_str(path: &std::path::Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| crate::Error::InvalidArgument("cramfs: non-UTF-8 path".into()))
}

impl crate::fs::FilesystemFactory for Cramfs {
    type FormatOpts = FormatOpts;

    fn format(dev: &mut dyn BlockDevice, opts: &Self::FormatOpts) -> Result<Self> {
        Self::format(dev, opts)
    }

    fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        Self::open(dev)
    }
}

impl Cramfs {
    fn writer(&mut self) -> Result<&mut writer::WriteState> {
        self.write_state.as_mut().ok_or(crate::Error::Immutable {
            kind: "cramfs",
            op: "write",
        })
    }
}

impl crate::fs::Filesystem for Cramfs {
    fn create_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        src: crate::fs::FileSource,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let p = path_str(path)?;
        let (mut r, len) = src.open()?;
        self.writer()?.create_file(dev, p, &mut r, len, meta)
    }

    fn create_file_streaming(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        body: &mut dyn Read,
        len: u64,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let p = path_str(path)?;
        self.writer()?.create_file(dev, p, body, len, meta)
    }

    fn create_dir(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let p = path_str(path)?;
        self.writer()?.create_dir(p, meta)
    }

    fn create_symlink(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        target: &std::path::Path,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let p = path_str(path)?;
        let t = target.to_str().ok_or_else(|| {
            crate::Error::InvalidArgument("cramfs: non-UTF-8 symlink target".into())
        })?;
        self.writer()?.create_symlink(dev, p, t, meta)
    }

    fn create_device(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        kind: crate::fs::DeviceKind,
        major: u32,
        minor: u32,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let p = path_str(path)?;
        self.writer()?.create_device(p, kind, major, minor, meta)
    }

    fn hardlink(
        &mut self,
        _dev: &mut dyn BlockDevice,
        target_path: &std::path::Path,
        new_path: &std::path::Path,
    ) -> Result<()> {
        let t = path_str(target_path)?;
        let n = path_str(new_path)?;
        self.writer()?.hardlink(t, n)
    }

    fn set_attrs(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        attrs: crate::fs::SetAttrs,
    ) -> Result<()> {
        let p = path_str(path)?;
        self.writer()?.set_attrs(p, attrs)
    }

    fn remove(&mut self, _dev: &mut dyn BlockDevice, _path: &std::path::Path) -> Result<()> {
        Err(crate::Error::Immutable {
            kind: "cramfs",
            op: "rm",
        })
    }

    fn list(&mut self, dev: &mut dyn BlockDevice, path: &std::path::Path) -> Result<Vec<DirEntry>> {
        self.list_path(dev, path_str(path)?)
    }

    fn read_file<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &std::path::Path,
    ) -> Result<Box<dyn Read + 'a>> {
        let p = path_str(path)?;
        self.open_file_reader(dev, p)
    }

    fn open_file_ro<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &std::path::Path,
    ) -> Result<Box<dyn crate::fs::FileReadHandle + 'a>> {
        let p = path_str(path)?;
        Ok(Box::new(self.open_file_read_handle(dev, p)?))
    }

    fn getattr(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
    ) -> Result<crate::fs::FileAttrs> {
        self.attrs(dev, path_str(path)?)
    }

    fn read_symlink(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
    ) -> Result<std::path::PathBuf> {
        Ok(Cramfs::read_symlink(self, dev, path_str(path)?)?.into())
    }

    fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        Cramfs::flush(self, dev)
    }

    /// The exact image length, so `create` / `repack` can trim the
    /// over-provisioned output.
    fn image_len(&self) -> Option<u64> {
        // The superblock's size counts any boot-sector pad in front of it.
        (self.write_state.is_none() && self.image_size > 0).then_some(self.image_size)
    }

    fn mutation_capability(&self) -> crate::fs::MutationCapability {
        crate::fs::MutationCapability::Immutable
    }
}

#[cfg(test)]
mod tests;
