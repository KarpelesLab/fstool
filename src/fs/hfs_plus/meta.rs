//! HFS+ authoring metadata: Finder info, resource forks, extended
//! attributes, entry identities (CNIDs) and creation dates.
//!
//! Everything here works on the handle's in-memory catalog, so it sees
//! entries created since the last [`HfsPlus::flush`] — the point of the
//! API is that a caller can lay down a tree, read back the CNIDs and
//! creation dates it was given (to build Finder aliases, say), add more
//! entries (a `.DS_Store` that embeds those aliases), and only then
//! flush. Flushing never renumbers CNIDs or rewrites dates: what
//! [`HfsPlus::entry_info`] reports before the flush is what macOS sees
//! after mounting.
//!
//! ## Where things live on disk
//!
//! * **Finder info** — 32 bytes inside each catalog record
//!   ([`FinderInfo`]). macOS surfaces it as the `com.apple.FinderInfo`
//!   xattr; it is never stored in the attributes B-tree.
//! * **Resource fork** — the file record's second fork, surfaced as the
//!   `com.apple.ResourceFork` xattr (and `file/..namedfork/rsrc`).
//! * **Other xattrs** — the attributes B-tree. Values up to
//!   [`max_inline_attr_size`](super::attributes::max_inline_attr_size)
//!   (3802 bytes with 8 KiB nodes) are stored inline, larger ones in
//!   their own extents — the same split xnu makes.
//!
//! Hard links: metadata calls on a hard-link path act on the shared
//! indirect-node (`iNode<N>`) record, which is where macOS keeps a
//! linked file's Finder info, xattrs, forks and dates.

use std::io::Read;

use crate::Result;
use crate::block::BlockDevice;

use super::HfsPlus;
use super::btree::ForkReader;
use super::catalog::{
    REC_FILE, REC_FOLDER, REC_FOLDER_THREAD, ROOT_FOLDER_ID, ROOT_PARENT_ID, UniStr, mode,
};
use super::extents::FORK_RESOURCE;
use super::finder::FinderInfo;
use super::volume_header::{FORK_DATA_SIZE, ForkData};
use super::writer::{self, OwnedKey, RSRC_FORK_OFF, Writer};

/// Seconds between the HFS+ epoch (1904-01-01 00:00:00 UTC) and the
/// Unix epoch.
const HFS_EPOCH_OFFSET: i64 = 2_082_844_800;

/// Convert Unix seconds to an HFS+ date (seconds since 1904-01-01 UTC),
/// clamping to the representable range.
pub fn hfs_date_from_unix(unix: i64) -> u32 {
    (unix + HFS_EPOCH_OFFSET).clamp(0, i64::from(u32::MAX)) as u32
}

/// Convert an HFS+ date (seconds since 1904-01-01 UTC) to Unix seconds.
pub fn unix_from_hfs_date(hfs: u32) -> i64 {
    i64::from(hfs) - HFS_EPOCH_OFFSET
}

/// The macOS-visible xattr name of a file's Finder info.
pub(crate) const XATTR_FINDER_INFO: &str = "com.apple.FinderInfo";
/// The macOS-visible xattr name of a file's resource fork.
pub(crate) const XATTR_RESOURCE_FORK: &str = "com.apple.ResourceFork";
/// HFS compression's payload attribute, hidden from `listxattr` by xnu.
const XATTR_DECMPFS: &str = "com.apple.decmpfs";

/// Identity and dates of one catalog entry, as returned by
/// [`HfsPlus::entry_info`]. Dates are raw HFS+ values: seconds since
/// 1904-01-01 00:00:00 UTC (see [`unix_from_hfs_date`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EntryInfo {
    /// Catalog node ID — what macOS reports as `st_ino` and what a
    /// Finder alias records as the target's file/folder ID. For a hard
    /// link this is the shared indirect node's CNID; the root is 2.
    pub cnid: u32,
    /// CNID of the containing folder (1 for the root folder).
    pub parent_cnid: u32,
    /// The name as stored on disk — HFS+-normalised (decomposed), in
    /// fstool's display form (a literal `/` shows as `:`). For the root
    /// this is the volume name.
    pub name: String,
    /// What kind of entry this is.
    pub kind: crate::fs::EntryKind,
    /// `createDate` (`st_birthtime`).
    pub create_date: u32,
    /// `contentModDate` (`st_mtime`).
    pub content_mod_date: u32,
    /// `attributeModDate` (`st_ctime`).
    pub attribute_mod_date: u32,
    /// `accessDate` (`st_atime`).
    pub access_date: u32,
    /// `backupDate`.
    pub backup_date: u32,
}

impl HfsPlus {
    fn meta_writer(&self) -> Result<&Writer> {
        self.writer
            .as_ref()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume is read-only".into()))
    }

    fn meta_writer_mut(&mut self) -> Result<&mut Writer> {
        self.writer
            .as_mut()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume is read-only".into()))
    }

    /// Catalog key of the file/folder record `path` names in the
    /// in-memory catalog (`"/"` is the root folder), plus the key of the
    /// record that holds its metadata — the same key, except for a hard
    /// link, where it is the shared `iNode<N>` record.
    fn meta_keys(&self, path: &str) -> Result<(OwnedKey, OwnedKey)> {
        let w = self.meta_writer()?;
        let key = if super::split_path(path).is_empty() {
            let thread = w
                .catalog
                .get(&OwnedKey::thread(ROOT_FOLDER_ID))
                .ok_or_else(|| {
                    crate::Error::InvalidImage("hfs+: root folder has no thread record".into())
                })?;
            if thread.len() < 10 || i16::from_be_bytes([thread[0], thread[1]]) != REC_FOLDER_THREAD
            {
                return Err(crate::Error::InvalidImage(
                    "hfs+: malformed root thread record".into(),
                ));
            }
            let (name, _) = UniStr::decode(&thread[8..])?;
            OwnedKey {
                parent_id: ROOT_PARENT_ID,
                name,
            }
        } else {
            let (parent_id, name) = self.resolve_create_target(path)?;
            OwnedKey { parent_id, name }
        };
        let body = w.catalog.get(&key).ok_or_else(|| {
            crate::Error::InvalidArgument(format!("hfs+: no such entry {path:?}"))
        })?;
        let rt = rec_type(body);
        if rt != REC_FILE && rt != REC_FOLDER {
            return Err(crate::Error::InvalidArgument(format!(
                "hfs+: {path:?} is not a file or folder record"
            )));
        }
        let target = if rt == REC_FILE && body.len() >= 56 && &body[48..56] == b"hlnkhfs+" {
            let inode = u32::from_be_bytes(body[44..48].try_into().unwrap());
            let private = w.private_dir_cnid.ok_or_else(|| {
                crate::Error::InvalidImage(
                    "hfs+: hard-link record but no HFS+ Private Data directory".into(),
                )
            })?;
            let ikey = OwnedKey {
                parent_id: private,
                name: UniStr::from_str_lossy(&format!("iNode{inode}")),
            };
            if !w.catalog.contains_key(&ikey) {
                return Err(crate::Error::InvalidImage(format!(
                    "hfs+: {path:?} links to missing iNode{inode}"
                )));
            }
            ikey
        } else {
            key.clone()
        };
        Ok((key, target))
    }

    /// Metadata record body for `path` (hard links resolved).
    fn meta_body(&self, path: &str) -> Result<&Vec<u8>> {
        let (_, target) = self.meta_keys(path)?;
        self.meta_writer()?
            .catalog
            .get(&target)
            .ok_or_else(|| crate::Error::InvalidArgument(format!("hfs+: no such entry {path:?}")))
    }

    fn meta_body_mut(&mut self, path: &str) -> Result<&mut Vec<u8>> {
        let (_, target) = self.meta_keys(path)?;
        self.meta_writer_mut()?
            .catalog
            .get_mut(&target)
            .ok_or_else(|| crate::Error::InvalidArgument(format!("hfs+: no such entry {path:?}")))
    }

    /// CNID whose attributes / forks `path` uses (hard links resolved).
    fn meta_cnid(&self, path: &str) -> Result<u32> {
        let body = self.meta_body(path)?;
        Ok(u32::from_be_bytes(body[8..12].try_into().unwrap()))
    }

    // ------------------------------------------------------------------
    // Identity and dates
    // ------------------------------------------------------------------

    /// CNID, name and dates of the entry at `path` (`"/"` for the root).
    ///
    /// Reflects the in-memory state, so it works between `create_*`
    /// calls and [`flush`](Self::flush). CNIDs are assigned once, at
    /// creation, and flushing never changes them or any date — the
    /// values reported here are exactly what the mounted volume reports
    /// (`stat -f %i`, `stat -f %B`).
    pub fn entry_info(&self, path: &str) -> Result<EntryInfo> {
        let (key, target) = self.meta_keys(path)?;
        let w = self.meta_writer()?;
        let body = w
            .catalog
            .get(&target)
            .expect("meta_keys checked the record");
        let is_dir = rec_type(body) == REC_FOLDER;
        let date = |i: usize| u32::from_be_bytes(body[12 + 4 * i..16 + 4 * i].try_into().unwrap());
        let file_mode = u16::from_be_bytes([body[42], body[43]]);
        let kind = if is_dir {
            crate::fs::EntryKind::Dir
        } else if body.len() >= 56 && &body[48..56] == b"slnkrhap" {
            crate::fs::EntryKind::Symlink
        } else {
            match file_mode & mode::S_IFMT {
                0 | mode::S_IFREG => crate::fs::EntryKind::Regular,
                mode::S_IFLNK => crate::fs::EntryKind::Symlink,
                mode::S_IFCHR => crate::fs::EntryKind::Char,
                mode::S_IFBLK => crate::fs::EntryKind::Block,
                mode::S_IFIFO => crate::fs::EntryKind::Fifo,
                mode::S_IFSOCK => crate::fs::EntryKind::Socket,
                _ => crate::fs::EntryKind::Unknown,
            }
        };
        Ok(EntryInfo {
            cnid: u32::from_be_bytes(body[8..12].try_into().unwrap()),
            parent_cnid: key.parent_id,
            name: key.name.to_display_name(),
            kind,
            create_date: date(0),
            content_mod_date: date(1),
            attribute_mod_date: date(2),
            access_date: date(3),
            backup_date: date(4),
        })
    }

    /// The volume's creation date as macOS reports it to applications
    /// (`getattrlist` `ATTR_VOL_CRTIME`, which is what a Finder alias
    /// records): the root folder's `createDate`, in HFS+ seconds (UTC).
    /// Set it with [`set_create_date`](Self::set_create_date) on `"/"`,
    /// or up front with [`FormatOpts::create_date`](super::FormatOpts).
    pub fn volume_create_date(&self) -> Result<u32> {
        Ok(self.entry_info("/")?.create_date)
    }

    /// Set the creation date (`createDate`, HFS+ seconds UTC — see
    /// [`hfs_date_from_unix`]) of the entry at `path`.
    ///
    /// Call it right after the `create_*` that made the entry: a fresh
    /// entry is otherwise stamped with
    /// [`FormatOpts::create_date`](super::FormatOpts). On the root
    /// (`"/"`) this also sets the volume header's `createDate`, so both
    /// views of the volume's age agree.
    pub fn set_create_date(&mut self, path: &str, date: u32) -> Result<()> {
        let is_root = super::split_path(path).is_empty();
        let body = self.meta_body_mut(path)?;
        body[12..16].copy_from_slice(&date.to_be_bytes());
        if is_root {
            self.meta_writer_mut()?.volume_create_date = date;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Finder info
    // ------------------------------------------------------------------

    /// The 32 Finder-info bytes of the entry at `path` (`"/"` for the
    /// root folder), exactly as stored in its catalog record.
    pub fn finder_info(&self, path: &str) -> Result<FinderInfo> {
        let body = self.meta_body(path)?;
        FinderInfo::from_slice(&body[48..80])
    }

    /// Replace the Finder info of the entry at `path` (`"/"` for the
    /// root folder — set [`flags::HAS_CUSTOM_ICON`] there to give the
    /// volume a `.VolumeIcon.icns` icon).
    ///
    /// All 32 bytes are stored as given, with one exception: a symbolic
    /// link keeps its `slnk`/`rhap` type and creator, which is how HFS+
    /// marks it as a link (macOS does the same).
    ///
    /// [`flags::HAS_CUSTOM_ICON`]: super::finder::flags::HAS_CUSTOM_ICON
    pub fn set_finder_info(&mut self, path: &str, info: &FinderInfo) -> Result<()> {
        let body = self.meta_body_mut(path)?;
        let symlink = is_symlink_body(body);
        let mut bytes = info.to_bytes();
        if symlink {
            bytes[0..8].copy_from_slice(b"slnkrhap");
        }
        body[48..80].copy_from_slice(&bytes);
        Ok(())
    }

    /// Finder info as xnu exposes it through `com.apple.FinderInfo`: the
    /// fields macOS keeps private (document ID, date added, write-gen
    /// counter, and a symlink's type/creator) zeroed; `None` when the
    /// rest is all zero (the attribute "does not exist").
    fn finder_info_xattr(&self, path: &str) -> Result<Option<[u8; 32]>> {
        let body = self.meta_body(path)?;
        let mut b: [u8; 32] = body[48..80].try_into().unwrap();
        b[16..24].fill(0);
        b[28..32].fill(0);
        if is_symlink_body(body) {
            b[0..8].fill(0);
        }
        Ok(if b.iter().all(|&x| x == 0) {
            None
        } else {
            Some(b)
        })
    }

    /// Store a `com.apple.FinderInfo` xattr value the way xnu does:
    /// the private fields of the existing record survive.
    fn set_finder_info_xattr(&mut self, path: &str, value: &[u8]) -> Result<()> {
        let new = FinderInfo::from_slice(value)?.to_bytes();
        let body = self.meta_body_mut(path)?;
        let mut merged = new;
        merged[16..24].copy_from_slice(&body[64..72]);
        merged[28..32].copy_from_slice(&body[76..80]);
        if is_symlink_body(body) {
            merged[0..8].copy_from_slice(b"slnkrhap");
        }
        body[48..80].copy_from_slice(&merged);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Resource forks
    // ------------------------------------------------------------------

    /// Resource fork of `path` as `(file_id, fork)`, or `None` when the
    /// entry is not a regular file, is HFS-compressed (its resource fork
    /// then holds `decmpfs` blocks), or has an empty resource fork.
    pub(crate) fn rsrc_fork_of(&self, path: &str) -> Result<Option<(u32, ForkData)>> {
        let body = self.meta_body(path)?;
        if rec_type(body) != REC_FILE || body.len() < RSRC_FORK_OFF + FORK_DATA_SIZE {
            return Ok(None);
        }
        if body[41] & super::decmpfs::UF_COMPRESSED != 0 {
            return Ok(None);
        }
        let mut buf = [0u8; FORK_DATA_SIZE];
        buf.copy_from_slice(&body[RSRC_FORK_OFF..RSRC_FORK_OFF + FORK_DATA_SIZE]);
        let fork = ForkData::decode(&buf);
        if fork.logical_size == 0 {
            return Ok(None);
        }
        Ok(Some((
            u32::from_be_bytes(body[8..12].try_into().unwrap()),
            fork,
        )))
    }

    /// A reader over `fork` of `file_id`, taking spilled extents from the
    /// in-memory extents-overflow records (so it works before a flush).
    pub(crate) fn writer_fork_reader(
        &self,
        fork: &ForkData,
        file_id: u32,
        fork_type: u8,
    ) -> Result<ForkReader> {
        let w = self.meta_writer()?;
        let bs = self.volume_header.block_size;
        if u64::from(fork.total_blocks) <= fork.inline_blocks() {
            return ForkReader::from_inline(fork, bs, "resource");
        }
        let extra: Vec<_> = w
            .overflow_extents
            .range((fork_type, file_id, 0)..=(fork_type, file_id, u32::MAX))
            .flat_map(|(_, g)| g.iter().copied().filter(|e| e.block_count != 0))
            .collect();
        ForkReader::from_inline_plus_overflow(fork, &extra, bs, "resource")
    }

    /// Replace the resource fork of the regular file at `path` with `len`
    /// bytes streamed from `src` (64 KiB at a time — never buffered
    /// whole). `len == 0` removes the resource fork. A hard link's fork
    /// is the shared iNode's.
    ///
    /// Errors on directories, symlinks, device nodes, and HFS-compressed
    /// files (whose resource fork belongs to `decmpfs`).
    pub fn write_resource_fork<R: Read + ?Sized>(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        src: &mut R,
        len: u64,
    ) -> Result<()> {
        let (_, target) = self.meta_keys(path)?;
        let w = self.meta_writer_mut()?;
        let body = w
            .catalog
            .get(&target)
            .expect("meta_keys checked the record");
        if rec_type(body) != REC_FILE || body.len() < RSRC_FORK_OFF + FORK_DATA_SIZE {
            return Err(crate::Error::InvalidArgument(format!(
                "hfs+: {path:?} is not a file; only regular files have resource forks"
            )));
        }
        let file_mode = u16::from_be_bytes([body[42], body[43]]);
        let fmt = file_mode & mode::S_IFMT;
        if is_symlink_body(body) || (fmt != 0 && fmt != mode::S_IFREG) {
            return Err(crate::Error::InvalidArgument(format!(
                "hfs+: {path:?} is not a regular file; only regular files have resource forks"
            )));
        }
        if body[41] & super::decmpfs::UF_COMPRESSED != 0 {
            return Err(crate::Error::Unsupported(format!(
                "hfs+: {path:?} is HFS-compressed; its resource fork holds decmpfs data"
            )));
        }
        let file_id = u32::from_be_bytes(body[8..12].try_into().unwrap());
        let mut buf = [0u8; FORK_DATA_SIZE];
        buf.copy_from_slice(&body[RSRC_FORK_OFF..RSRC_FORK_OFF + FORK_DATA_SIZE]);
        let old = ForkData::decode(&buf);
        // Drop the old fork first: its extents-overflow records share the
        // (fork type, file ID) key space the new fork's would use.
        writer::free_fork(w, &old, FORK_RESOURCE, file_id);
        set_rsrc_fork(w, &target, &ForkData::default());
        let fork = writer::stream_fork_to_blocks(w, dev, src, len, file_id, FORK_RESOURCE)?;
        set_rsrc_fork(w, &target, &fork);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Extended attributes
    // ------------------------------------------------------------------

    /// Names of the extended attributes of `path`, in the order macOS
    /// lists them: `com.apple.FinderInfo` (when non-zero) and
    /// `com.apple.ResourceFork` (when non-empty) first, then the
    /// attributes B-tree in key order. `com.apple.decmpfs` is hidden, as
    /// xnu hides it.
    pub fn list_xattr_names(&self, path: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        if self.finder_info_xattr(path)?.is_some() {
            out.push(XATTR_FINDER_INFO.to_string());
        }
        if self.rsrc_fork_of(path)?.is_some() {
            out.push(XATTR_RESOURCE_FORK.to_string());
        }
        let cnid = self.meta_cnid(path)?;
        for name in writer::list_attr_names(self.meta_writer()?, cnid) {
            let s = String::from_utf16_lossy(&name);
            if s != XATTR_DECMPFS {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// Value of extended attribute `name` on `path`, or `None` when it is
    /// not set. `com.apple.FinderInfo` and `com.apple.ResourceFork` are
    /// synthesised from the catalog record, as on macOS.
    pub fn get_xattr(
        &self,
        dev: &mut dyn BlockDevice,
        path: &str,
        name: &str,
    ) -> Result<Option<Vec<u8>>> {
        match name {
            XATTR_FINDER_INFO => Ok(self.finder_info_xattr(path)?.map(|b| b.to_vec())),
            XATTR_RESOURCE_FORK => {
                let Some((file_id, fork)) = self.rsrc_fork_of(path)? else {
                    return Ok(None);
                };
                let len = super::cap_alloc(dev, fork.logical_size, "resource fork")?;
                let reader = self.writer_fork_reader(&fork, file_id, FORK_RESOURCE)?;
                let mut buf = vec![0u8; len];
                reader.read(dev, 0, &mut buf)?;
                Ok(Some(buf))
            }
            _ => {
                let cnid = self.meta_cnid(path)?;
                let units: Vec<u16> = name.encode_utf16().collect();
                writer::get_attr(self.meta_writer()?, dev, cnid, &units)
            }
        }
    }

    /// Set extended attribute `name` on `path` (any file, folder or the
    /// root `"/"`), replacing an existing value.
    ///
    /// * `com.apple.FinderInfo` must be exactly 32 bytes and updates the
    ///   catalog record's Finder info (keeping the fields macOS keeps
    ///   private, as `setxattr` does);
    /// * `com.apple.ResourceFork` replaces the resource fork (for large
    ///   forks prefer the streaming [`write_resource_fork`](Self::write_resource_fork));
    /// * anything else goes to the attributes B-tree: names are 1‥127
    ///   UTF-16 code units, stored verbatim (xnu does not normalise
    ///   attribute names); values up to 3802 bytes (8 KiB nodes) are
    ///   stored inline, larger ones in extents of their own.
    ///
    /// Values that cannot be stored produce an error — nothing is ever
    /// silently dropped.
    pub fn set_xattr(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        name: &str,
        value: &[u8],
    ) -> Result<()> {
        match name {
            XATTR_FINDER_INFO => self.set_finder_info_xattr(path, value),
            XATTR_RESOURCE_FORK => {
                let mut cur = std::io::Cursor::new(value);
                self.write_resource_fork(dev, path, &mut cur, value.len() as u64)
            }
            _ => {
                let cnid = self.meta_cnid(path)?;
                let units: Vec<u16> = name.encode_utf16().collect();
                writer::set_attr(self.meta_writer_mut()?, dev, cnid, &units, value)
            }
        }
    }

    /// Remove extended attribute `name` from `path`. Returns whether it
    /// existed. Removing `com.apple.FinderInfo` zeroes the (public part
    /// of the) Finder info; removing `com.apple.ResourceFork` empties
    /// the resource fork.
    pub fn remove_xattr(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        name: &str,
    ) -> Result<bool> {
        match name {
            XATTR_FINDER_INFO => {
                let existed = self.finder_info_xattr(path)?.is_some();
                if existed {
                    self.set_finder_info_xattr(path, &[0u8; 32])?;
                }
                Ok(existed)
            }
            XATTR_RESOURCE_FORK => {
                let existed = self.rsrc_fork_of(path)?.is_some();
                if existed {
                    self.write_resource_fork(dev, path, &mut std::io::empty(), 0)?;
                }
                Ok(existed)
            }
            _ => {
                let cnid = self.meta_cnid(path)?;
                let units: Vec<u16> = name.encode_utf16().collect();
                writer::remove_attr(self.meta_writer_mut()?, cnid, &units)
            }
        }
    }
}

fn rec_type(body: &[u8]) -> i16 {
    if body.len() < 2 {
        0
    } else {
        i16::from_be_bytes([body[0], body[1]])
    }
}

fn is_symlink_body(body: &[u8]) -> bool {
    rec_type(body) == REC_FILE && body.len() >= 56 && &body[48..56] == b"slnkrhap"
}

fn set_rsrc_fork(w: &mut Writer, key: &OwnedKey, fork: &ForkData) {
    if let Some(body) = w.catalog.get_mut(key) {
        let mut enc = Vec::with_capacity(FORK_DATA_SIZE);
        enc.extend_from_slice(&fork.logical_size.to_be_bytes());
        enc.extend_from_slice(&fork.clump_size.to_be_bytes());
        enc.extend_from_slice(&fork.total_blocks.to_be_bytes());
        for e in &fork.extents {
            enc.extend_from_slice(&e.start_block.to_be_bytes());
            enc.extend_from_slice(&e.block_count.to_be_bytes());
        }
        body[RSRC_FORK_OFF..RSRC_FORK_OFF + FORK_DATA_SIZE].copy_from_slice(&enc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;
    use crate::fs::hfs_plus::finder::flags;
    use crate::fs::hfs_plus::writer::FormatOpts;

    fn fresh(create_date: u32) -> (MemoryBackend, HfsPlus) {
        let mut dev = MemoryBackend::new(16 * 1024 * 1024);
        let opts = FormatOpts {
            create_date,
            volume_name: "Meta".into(),
            ..FormatOpts::default()
        };
        let hfs = HfsPlus::format(&mut dev, &opts).unwrap();
        (dev, hfs)
    }

    fn file(hfs: &mut HfsPlus, dev: &mut MemoryBackend, path: &str, data: &[u8]) -> u32 {
        let mut src = std::io::Cursor::new(data);
        hfs.create_file(dev, path, &mut src, data.len() as u64, 0o644, 0, 0, 0)
            .unwrap()
    }

    fn read_rsrc(hfs: &HfsPlus, dev: &mut MemoryBackend, path: &str) -> Vec<u8> {
        let mut r = hfs.open_resource_fork_reader(dev, path).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        buf
    }

    #[test]
    fn identities_and_metadata_survive_flush_and_reopen() {
        let base = hfs_date_from_unix(1_700_000_000);
        let (mut dev, mut hfs) = fresh(base);
        hfs.create_dir(&mut dev, "/App.app", 0o755, 0, 0, 0)
            .unwrap();
        let cnid = file(&mut hfs, &mut dev, "/App.app/a.txt", b"hello");

        // Identity before flush.
        let info = hfs.entry_info("/App.app/a.txt").unwrap();
        assert_eq!(info.cnid, cnid);
        assert_eq!(
            info.create_date, base,
            "default stamp is FormatOpts::create_date"
        );
        assert_eq!(hfs.volume_create_date().unwrap(), base);
        let root = hfs.entry_info("/").unwrap();
        assert_eq!(root.cnid, 2);
        assert_eq!(root.name, "Meta");

        // Per-entry creation date.
        hfs.set_create_date("/App.app/a.txt", base + 77).unwrap();

        // Finder info on file, folder and root.
        let mut fi = FinderInfo::default();
        fi.set_file_type(*b"TEXT");
        fi.set_creator(*b"ttxt");
        fi.set_finder_flags(flags::HAS_BEEN_INITED);
        hfs.set_finder_info("/App.app/a.txt", &fi).unwrap();
        let mut dir_fi = FinderInfo::default();
        dir_fi.set_finder_flags(flags::HAS_BUNDLE);
        hfs.set_finder_info("/App.app", &dir_fi).unwrap();
        let mut root_fi = FinderInfo::default();
        root_fi.set_finder_flags(flags::HAS_CUSTOM_ICON);
        hfs.set_finder_info("/", &root_fi).unwrap();

        // Resource fork (multi-block) and xattrs: inline, extent-based,
        // and on the root.
        let rsrc: Vec<u8> = (0..20_000u32).map(|i| (i * 7) as u8).collect();
        hfs.write_resource_fork(
            &mut dev,
            "/App.app/a.txt",
            &mut &rsrc[..],
            rsrc.len() as u64,
        )
        .unwrap();
        hfs.set_xattr(&mut dev, "/App.app/a.txt", "user.small", b"hi")
            .unwrap();
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        hfs.set_xattr(&mut dev, "/App.app/a.txt", "com.example.big", &big)
            .unwrap();
        hfs.set_xattr(&mut dev, "/", "com.example.root", b"r")
            .unwrap();

        // Everything readable before the flush.
        assert_eq!(read_rsrc(&hfs, &mut dev, "/App.app/a.txt"), rsrc);
        assert_eq!(
            hfs.get_xattr(&mut dev, "/App.app/a.txt", "com.example.big")
                .unwrap()
                .unwrap(),
            big
        );
        let before = hfs.entry_info("/App.app/a.txt").unwrap();
        assert_eq!(before.create_date, base + 77);

        hfs.flush(&mut dev).unwrap();

        // Post-flush generated file; earlier identities unchanged.
        let ds = file(&mut hfs, &mut dev, "/App.app/.DS_Store", b"Bud1");
        assert_ne!(ds, cnid);
        hfs.flush(&mut dev).unwrap();

        let hfs = HfsPlus::open(&mut dev).unwrap();
        assert_eq!(hfs.entry_info("/App.app/a.txt").unwrap(), before);
        assert_eq!(hfs.entry_info("/App.app/.DS_Store").unwrap().cnid, ds);
        assert_eq!(hfs.volume_create_date().unwrap(), base);
        assert_eq!(hfs.finder_info("/App.app/a.txt").unwrap(), fi);
        assert_eq!(hfs.finder_info("/App.app").unwrap(), dir_fi);
        assert_eq!(hfs.finder_info("/").unwrap(), root_fi);
        assert_eq!(read_rsrc(&hfs, &mut dev, "/App.app/a.txt"), rsrc);
        assert_eq!(
            hfs.list_xattr_names("/App.app/a.txt").unwrap(),
            vec![
                "com.apple.FinderInfo",
                "com.apple.ResourceFork",
                "com.example.big",
                "user.small"
            ]
        );
        assert_eq!(
            hfs.get_xattr(&mut dev, "/App.app/a.txt", "com.example.big")
                .unwrap()
                .unwrap(),
            big
        );
        assert_eq!(
            hfs.get_xattr(&mut dev, "/App.app/a.txt", "user.small")
                .unwrap()
                .unwrap(),
            b"hi"
        );
        assert_eq!(
            hfs.get_xattr(&mut dev, "/", "com.example.root")
                .unwrap()
                .unwrap(),
            b"r"
        );
        // The read-only attributes walker agrees with the writer view.
        let attrs = hfs.attributes.as_ref().expect("attributes B-tree written");
        match attrs.lookup(&mut dev, 2, "com.example.root").unwrap() {
            Some(crate::fs::hfs_plus::attributes::AttrRecord::Inline { data }) => {
                assert_eq!(data, b"r")
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn xattr_replace_remove_and_entry_removal_free_blocks() {
        let (mut dev, mut hfs) = fresh(0);
        file(&mut hfs, &mut dev, "/f", b"x");
        let free0 = hfs.writer.as_ref().unwrap().free_blocks;
        let big = vec![0xAB; 50_000];
        hfs.set_xattr(&mut dev, "/f", "user.big", &big).unwrap();
        let free1 = hfs.writer.as_ref().unwrap().free_blocks;
        assert_eq!(free0 - free1, 50_000u32.div_ceil(4096));
        // Replace with an inline value: blocks come back.
        hfs.set_xattr(&mut dev, "/f", "user.big", b"small").unwrap();
        assert_eq!(hfs.writer.as_ref().unwrap().free_blocks, free0);
        assert!(hfs.remove_xattr(&mut dev, "/f", "user.big").unwrap());
        assert!(!hfs.remove_xattr(&mut dev, "/f", "user.big").unwrap());
        assert_eq!(hfs.get_xattr(&mut dev, "/f", "user.big").unwrap(), None);

        hfs.set_xattr(&mut dev, "/f", "user.big", &big).unwrap();
        let r = vec![1u8; 9000];
        hfs.write_resource_fork(&mut dev, "/f", &mut &r[..], 9000)
            .unwrap();
        hfs.remove(&mut dev, "/f").unwrap();
        assert!(hfs.writer.as_ref().unwrap().attrs.is_empty());
        hfs.flush(&mut dev).unwrap();
        let hfs = HfsPlus::open(&mut dev).unwrap();
        assert!(hfs.writer.as_ref().unwrap().attrs.is_empty());
    }

    #[test]
    fn xattr_special_names_and_errors() {
        let (mut dev, mut hfs) = fresh(0);
        file(&mut hfs, &mut dev, "/f", b"x");
        hfs.create_symlink(&mut dev, "/l", "f", 0o755, 0, 0, 0)
            .unwrap();
        hfs.create_dir(&mut dev, "/d", 0o755, 0, 0, 0).unwrap();

        // FinderInfo through the xattr view: 32 bytes only.
        assert!(
            hfs.set_xattr(&mut dev, "/f", "com.apple.FinderInfo", &[1; 31])
                .is_err()
        );
        let mut fi = [0u8; 32];
        fi[0..8].copy_from_slice(b"APPLMACS");
        fi[20] = 9; // private (date added): not settable through the xattr
        hfs.set_xattr(&mut dev, "/f", "com.apple.FinderInfo", &fi)
            .unwrap();
        let got = hfs
            .get_xattr(&mut dev, "/f", "com.apple.FinderInfo")
            .unwrap()
            .unwrap();
        assert_eq!(&got[0..8], b"APPLMACS");
        assert_eq!(got[20], 0);
        // A symlink keeps its link type; with nothing else set the
        // attribute does not exist.
        assert_eq!(
            hfs.get_xattr(&mut dev, "/l", "com.apple.FinderInfo")
                .unwrap(),
            None
        );
        hfs.set_finder_info("/l", &FinderInfo::from_bytes([0x11; 32]))
            .unwrap();
        assert_eq!(
            &hfs.finder_info("/l").unwrap().to_bytes()[0..8],
            b"slnkrhap"
        );

        // Resource forks only on regular files.
        assert!(
            hfs.set_xattr(&mut dev, "/d", "com.apple.ResourceFork", b"x")
                .is_err()
        );
        assert!(
            hfs.write_resource_fork(&mut dev, "/l", &mut &b"x"[..], 1)
                .is_err()
        );
        hfs.set_xattr(&mut dev, "/f", "com.apple.ResourceFork", b"RSRC")
            .unwrap();
        assert_eq!(
            hfs.get_xattr(&mut dev, "/f", "com.apple.ResourceFork")
                .unwrap()
                .unwrap(),
            b"RSRC"
        );
        assert!(
            hfs.remove_xattr(&mut dev, "/f", "com.apple.ResourceFork")
                .unwrap()
        );
        assert_eq!(hfs.resource_fork_size(&mut dev, "/f").unwrap(), None);

        // Name limits are reported, not truncated.
        let long = "n".repeat(128);
        assert!(hfs.set_xattr(&mut dev, "/f", &long, b"v").is_err());
        assert!(hfs.set_xattr(&mut dev, "/f", "", b"v").is_err());
        assert!(hfs.set_xattr(&mut dev, "/nope", "user.x", b"v").is_err());
        // Directories and symlinks take xattrs.
        hfs.set_xattr(&mut dev, "/d", "user.x", b"1").unwrap();
        hfs.set_xattr(&mut dev, "/l", "user.x", b"2").unwrap();
        hfs.flush(&mut dev).unwrap();
        let mut hfs = HfsPlus::open(&mut dev).unwrap();
        assert_eq!(
            hfs.get_xattr(&mut dev, "/l", "user.x").unwrap().unwrap(),
            b"2"
        );
        // Through the generic trait as well.
        let pairs =
            crate::fs::Filesystem::list_xattrs(&mut hfs, &mut dev, std::path::Path::new("/d"))
                .unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].name, "user.x");
    }

    #[test]
    fn names_are_normalised_and_collisions_rejected() {
        let (mut dev, mut hfs) = fresh(0);
        // NFC input is stored decomposed.
        file(&mut hfs, &mut dev, "/caf\u{e9}", b"1");
        hfs.flush(&mut dev).unwrap();
        let names: Vec<String> = hfs
            .list_path(&mut dev, "/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"cafe\u{301}".to_string()), "{names:?}");
        // Either spelling finds it.
        assert_eq!(hfs.entry_info("/caf\u{e9}").unwrap().name, "cafe\u{301}");
        assert!(hfs.entry_info("/cafe\u{301}").is_ok());
        // Canonically-equivalent and case-folded names collide.
        let mut src = std::io::Cursor::new(b"2");
        assert!(
            hfs.create_file(&mut dev, "/cafe\u{301}", &mut src, 1, 0o644, 0, 0, 0)
                .is_err()
        );
        let mut src = std::io::Cursor::new(b"2");
        assert!(
            hfs.create_file(&mut dev, "/CAF\u{c9}", &mut src, 1, 0o644, 0, 0, 0)
                .is_err()
        );
        // Excluded ranges stay as given: Ω (U+2126) is not Ω (U+03A9).
        file(&mut hfs, &mut dev, "/\u{2126}", b"ohm");
        assert_eq!(hfs.entry_info("/\u{2126}").unwrap().name, "\u{2126}");
        file(&mut hfs, &mut dev, "/\u{3a9}", b"omega");
        // Length counts after decomposition.
        let mut src = std::io::Cursor::new(b"");
        let long = "\u{e9}".repeat(128);
        assert!(
            hfs.create_file(&mut dev, &format!("/{long}"), &mut src, 0, 0o644, 0, 0, 0)
                .is_err()
        );
        hfs.flush(&mut dev).unwrap();
        let hfs = HfsPlus::open(&mut dev).unwrap();
        let mut r = hfs.open_file_reader(&mut dev, "/caf\u{e9}").unwrap();
        let mut b = Vec::new();
        r.read_to_end(&mut b).unwrap();
        assert_eq!(b, b"1");
    }

    #[test]
    fn fragmented_values_use_overflow_records() {
        let mut dev = MemoryBackend::new(8 * 1024 * 1024);
        let opts = FormatOpts {
            attributes_nodes: 4,
            ..FormatOpts::default()
        };
        let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
        let one = [7u8; 4096];
        for i in 0..21 {
            file(&mut hfs, &mut dev, &format!("/s{i:02}"), &one);
        }
        file(&mut hfs, &mut dev, "/t", b"t");
        let fill = hfs.free_bytes();
        let mut z = std::io::repeat(0).take(fill);
        hfs.create_file(&mut dev, "/filler", &mut z, fill, 0o644, 0, 0, 0)
            .unwrap();
        for i in (1..21).step_by(2) {
            hfs.remove(&mut dev, &format!("/s{i:02}")).unwrap();
        }
        let xv: Vec<u8> = (0..10 * 4096u32).map(|i| (i % 253) as u8).collect();
        hfs.set_xattr(&mut dev, "/t", "user.frag", &xv).unwrap();
        let w = hfs.writer.as_ref().unwrap();
        let cnid = hfs.entry_info("/t").unwrap().cnid;
        assert!(
            w.attrs.keys().any(|k| k.0 == cnid && k.2 == 8),
            "expected an HFSPlusAttrExtents record at startBlock 8"
        );
        hfs.flush(&mut dev).unwrap();
        let hfs = HfsPlus::open(&mut dev).unwrap();
        assert_eq!(
            hfs.get_xattr(&mut dev, "/t", "user.frag").unwrap().unwrap(),
            xv
        );
    }

    #[test]
    fn journaled_reopen_creates_attributes_tree_through_the_journal() {
        let mut dev = MemoryBackend::new(32 * 1024 * 1024);
        let opts = FormatOpts {
            journaled: true,
            ..FormatOpts::default()
        };
        let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
        file(&mut hfs, &mut dev, "/f", b"x");
        hfs.flush(&mut dev).unwrap();
        let mut hfs = HfsPlus::open(&mut dev).unwrap();
        hfs.set_xattr(&mut dev, "/f", "user.j", b"journaled")
            .unwrap();
        hfs.set_finder_info("/f", &FinderInfo::from_bytes([3; 32]))
            .unwrap();
        hfs.flush(&mut dev).unwrap();
        let hfs = HfsPlus::open(&mut dev).unwrap();
        assert_eq!(
            hfs.get_xattr(&mut dev, "/f", "user.j").unwrap().unwrap(),
            b"journaled"
        );
        assert_eq!(hfs.finder_info("/f").unwrap().to_bytes(), [3; 32]);
    }

    #[test]
    fn hard_link_metadata_lives_on_the_inode() {
        let (mut dev, mut hfs) = fresh(0);
        file(&mut hfs, &mut dev, "/a", b"data");
        let inode = hfs.create_hardlink(&mut dev, "/a", "/b").unwrap();
        assert_eq!(hfs.entry_info("/a").unwrap().cnid, inode);
        assert_eq!(hfs.entry_info("/b").unwrap().cnid, inode);
        hfs.set_xattr(&mut dev, "/a", "user.k", b"v").unwrap();
        assert_eq!(
            hfs.get_xattr(&mut dev, "/b", "user.k").unwrap().unwrap(),
            b"v"
        );
    }
}
