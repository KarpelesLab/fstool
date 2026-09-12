//! Unified read-side API: probe an image, identify the filesystem on it,
//! and expose a small inspection surface (list / cat / info) that the CLI
//! can drive without knowing which filesystem it's talking to.
//!
//! The probe is deliberately minimal — it reads a couple of well-known
//! offsets and matches magic numbers. It is *not* a full mountability
//! check; opening the image with the chosen backend is still where actual
//! validation happens.

use std::path::{Path, PathBuf};

use crate::Result;
use crate::block::BlockDevice;
use crate::fs::DirEntry;
#[cfg(feature = "affs")]
use crate::fs::affs::Affs;
#[cfg(feature = "apfs")]
use crate::fs::apfs::Apfs;
#[cfg(feature = "archive")]
use crate::fs::archive::ar::ArFs;
#[cfg(feature = "arc")]
use crate::fs::archive::arc::ArcFs;
#[cfg(feature = "cab")]
use crate::fs::archive::cab::CabFs;
#[cfg(feature = "archive")]
use crate::fs::archive::cpio::CpioFs;
#[cfg(feature = "lha")]
use crate::fs::archive::lha::LhaFs;
#[cfg(feature = "amiga-lzx")]
use crate::fs::archive::lzx::LzxFs;
#[cfg(feature = "rar")]
use crate::fs::archive::rar::RarFs;
#[cfg(feature = "sevenz")]
use crate::fs::archive::sevenz::SevenZFs;
#[cfg(feature = "sit")]
use crate::fs::archive::sit::SitFs;
#[cfg(feature = "archive")]
use crate::fs::archive::zip::ZipFs;
#[cfg(feature = "exfat")]
use crate::fs::exfat::Exfat;
#[cfg(feature = "ext")]
use crate::fs::ext::Ext;
#[cfg(feature = "f2fs")]
use crate::fs::f2fs::F2fs;
#[cfg(feature = "fat")]
use crate::fs::fat::Fat32;
#[cfg(feature = "hfs")]
use crate::fs::hfs::Hfs;
#[cfg(feature = "hfs-plus")]
use crate::fs::hfs_plus::HfsPlus;
#[cfg(feature = "littlefs")]
use crate::fs::littlefs::LittleFs;
#[cfg(feature = "ntfs")]
use crate::fs::ntfs::Ntfs;
#[cfg(feature = "ramfs")]
use crate::fs::ramfs::Ramfs;
#[cfg(feature = "squashfs")]
use crate::fs::squashfs::Squashfs;
#[cfg(feature = "tar")]
use crate::fs::tar::Tar;
#[cfg(feature = "xfs")]
use crate::fs::xfs::Xfs;
use crate::part::{Apm, Gpt, Mbr, Partition, PartitionTable, slice_partition};

/// Which filesystem an image carries.
///
/// `#[non_exhaustive]` because new filesystems get added over time;
/// external code that needs to dispatch on the kind should keep a
/// fallback arm. Most callers want [`open`] or [`summary`] instead —
/// those return a `Box<dyn Filesystem>` / [`Summary`] that hide the
/// concrete backend entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FsKind {
    /// ext2 / ext3 / ext4 — distinguished further by feature flags.
    #[cfg(feature = "ext")]
    Ext,
    /// The FAT family — FAT12, FAT16 and FAT32. One backend
    /// ([`crate::fs::fat::Fat32`]) drives all three; ask the opened
    /// volume's `kind()` which flavour it actually is.
    #[cfg(feature = "fat")]
    Fat32,
    /// A tar archive treated as a read-only filesystem.
    #[cfg(feature = "tar")]
    Tar,
    /// XFS — read-only (shortform dirs + extent files).
    #[cfg(feature = "xfs")]
    Xfs,
    /// exFAT — read-only.
    #[cfg(feature = "exfat")]
    Exfat,
    /// HFS+ — read-only.
    #[cfg(feature = "hfs-plus")]
    HfsPlus,
    /// Classic HFS (Mac OS ≤ 8) — read + write (create / in-place add/remove).
    #[cfg(feature = "hfs")]
    Hfs,
    /// Amiga OFS/FFS (AFFS) — read-only (write lands in later phases).
    #[cfg(feature = "affs")]
    Affs,
    /// littlefs — read + write, including in-place edits.
    #[cfg(feature = "littlefs")]
    LittleFs,
    /// APFS — read-only, single-leaf-tree case only.
    #[cfg(feature = "apfs")]
    Apfs,
    /// NTFS — read + write (MFT, attributes, `$DATA` + ADS, indexes,
    /// `$Secure`, `$LogFile`).
    #[cfg(feature = "ntfs")]
    Ntfs,
    /// F2FS — read + write (build-once: a re-opened image is read-only).
    #[cfg(feature = "f2fs")]
    F2fs,
    /// SquashFS — read + write via `repack` (compressed, repack-only).
    #[cfg(feature = "squashfs")]
    Squashfs,
    /// ISO 9660 (optical media). Read-only on this trait surface;
    /// writing happens through `repack` to a fresh image.
    #[cfg(feature = "iso9660")]
    Iso9660,
    /// GRF — Gravity Ragnarok Online archive. Read + write + add/rm.
    #[cfg(feature = "grf")]
    Grf,
    /// ZIP archive. Read + repack (write via `repack`).
    #[cfg(feature = "archive")]
    Zip,
    /// cpio archive (newc / odc). Read + repack.
    #[cfg(feature = "archive")]
    Cpio,
    /// Unix `ar` archive. Read + repack.
    #[cfg(feature = "archive")]
    Ar,
    /// 7-Zip — detection-only scaffold.
    #[cfg(feature = "sevenz")]
    SevenZ,
    /// RAR — detection-only scaffold.
    #[cfg(feature = "rar")]
    Rar,
    /// SEA ARC — detection-only scaffold.
    #[cfg(feature = "arc")]
    Arc,
    /// LHA / LZH — detection-only scaffold.
    #[cfg(feature = "lha")]
    Lha,
    /// Amiga LZX — detection-only scaffold.
    #[cfg(feature = "amiga-lzx")]
    Lzx,
    /// Microsoft Cabinet — detection-only scaffold.
    #[cfg(feature = "cab")]
    Cab,
    /// StuffIt — detection-only scaffold.
    #[cfg(feature = "sit")]
    Sit,
    /// In-memory ramfs. Has no on-disk form, so it is never returned by
    /// [`detect_fs`] — only constructed explicitly (`AnyFs::new_ramfs`).
    #[cfg(feature = "ramfs")]
    Ramfs,
}

/// The error for a format whose on-disk signature was recognised (or whose
/// name was asked for) but whose backend is compiled out of this build:
/// `what` is the human-readable format name ("XFS"), `feature` the Cargo
/// feature that brings it back. Shared by [`detect_fs`] and the
/// name-driven dispatch sites so the message stays uniform.
pub fn missing_feature(what: &str, feature: &str) -> crate::Error {
    crate::Error::Unsupported(format!(
        "{what} detected, but this build of fstool was compiled without the `{feature}` feature"
    ))
}

/// `return Ok(FsKind::$variant)` when the backend behind `$feature` is
/// compiled in; otherwise return the [`missing_feature`] error. The magic
/// check itself always runs, so a recognised-but-unavailable image is
/// reported as such instead of as "no recognised filesystem".
macro_rules! detected {
    ($feature:literal, $variant:ident, $what:literal) => {{
        #[cfg(feature = $feature)]
        {
            return Ok(FsKind::$variant);
        }
        #[cfg(not(feature = $feature))]
        {
            return Err(missing_feature($what, $feature));
        }
    }};
}

/// Probe `dev` to decide which filesystem it carries. Reads only sector 0
/// and the ext superblock at byte 1024; no mutation, no full open.
pub fn detect_fs(dev: &mut dyn BlockDevice) -> Result<FsKind> {
    // FAT32 first: cheap, only 90 bytes of sector 0, signature is very
    // specific ("FAT32" at +82 and 0x55AA at +510). An ext superblock
    // could in principle live on a disk that also has a sector-0 boot
    // sector, but ext images start with all-zero (mke2fs leaves the first
    // 1024 bytes for boot code), so a real FAT32 signature here is decisive.
    // Read up to the first sector. Small archives (a tiny `ar`, an empty
    // zip) can be well under 512 bytes, so only read what's there and
    // leave the rest of the buffer zero — the magic checks below then
    // simply don't match on the absent bytes.
    let mut bs = [0u8; 512];
    let head = (dev.total_size()).min(512) as usize;
    dev.read_at(0, &mut bs[..head])?;
    if bs[510] == 0x55 && bs[511] == 0xAA && &bs[82..87] == b"FAT32" {
        detected!("fat", Fat32, "FAT32");
    }
    // exFAT: "EXFAT   " at offset 3 of LBA 0 (also has 0x55AA at +510).
    if &bs[3..11] == b"EXFAT   " {
        detected!("exfat", Exfat, "exFAT");
    }
    // NTFS: "NTFS    " at offset 3 of LBA 0.
    if &bs[3..11] == b"NTFS    " {
        detected!("ntfs", Ntfs, "NTFS");
    }

    // FAT12 / FAT16 have no magic string at all — their flavour follows
    // from the cluster count — so this probe validates the whole BPB plus
    // the jump instruction and media byte. It runs after exFAT and NTFS
    // because those carry a FAT-shaped sector 0 with their own signature,
    // and before the remaining checks because those key off offsets a FAT
    // boot sector doesn't use.
    #[cfg(feature = "fat")]
    if crate::fs::fat::boot::probe(&bs).is_some() {
        return Ok(FsKind::Fat32);
    }

    // XFS: "XFSB" at offset 0 of LBA 0.
    if &bs[0..4] == b"XFSB" {
        detected!("xfs", Xfs, "XFS");
    }

    // SquashFS: little-endian "hsqs" at offset 0.
    if &bs[0..4] == b"hsqs" {
        detected!("squashfs", Squashfs, "SquashFS");
    }

    // GRF: "Master of Magic\0" at offset 0 (16-byte magic header).
    if &bs[0..16] == b"Master of Magic\0" {
        detected!("grf", Grf, "GRF");
    }

    // littlefs: the superblock entry is always the first tag of block 0's
    // first commit, which puts the magic string at exactly offset 8.
    if &bs[8..16] == b"littlefs" {
        detected!("littlefs", LittleFs, "littlefs");
    }

    // Amiga OFS/FFS: boot block "DOS" + a flag byte 0..=7 at offset 0.
    // Specific enough to not shadow MBR/boot sectors (which don't begin
    // with "DOS"); the flag byte's high bits being zero rules out ASCII.
    if &bs[0..3] == b"DOS" && bs[3] <= 7 {
        detected!("affs", Affs, "Amiga FFS");
    }

    // --- archive formats (all offset 0 except lha at offset 2) ---
    // ZIP: local-file-header "PK\x03\x04" or an empty archive's EOCD
    // "PK\x05\x06".
    if &bs[0..2] == b"PK" && ((bs[2] == 3 && bs[3] == 4) || (bs[2] == 5 && bs[3] == 6)) {
        detected!("archive", Zip, "ZIP");
    }
    // cpio: newc "070701" / newc-crc "070702" / odc "070707".
    if &bs[0..6] == b"070701" || &bs[0..6] == b"070702" || &bs[0..6] == b"070707" {
        detected!("archive", Cpio, "cpio");
    }
    // ar: "!<arch>\n".
    if &bs[0..8] == b"!<arch>\n" {
        detected!("archive", Ar, "ar");
    }
    // 7z: "7z\xBC\xAF\x27\x1C".
    if &bs[0..6] == b"7z\xBC\xAF\x27\x1C" {
        detected!("sevenz", SevenZ, "7-Zip");
    }
    // RAR: "Rar!\x1A\x07" then 0x00 (v4) or 0x01 (v5).
    if &bs[0..6] == b"Rar!\x1A\x07" {
        detected!("rar", Rar, "RAR");
    }
    // Microsoft Cabinet: "MSCF".
    if &bs[0..4] == b"MSCF" {
        detected!("cab", Cab, "Microsoft Cabinet");
    }
    // LHA / LZH: method tag "-lh?-" / "-lz?-" at offset 2 (bytes 0..2 are
    // header size + checksum), with the trailing '-' at offset 6.
    if &bs[2..4] == b"-l" && bs[6] == b'-' {
        detected!("lha", Lha, "LHA");
    }
    // Amiga LZX: "LZX\0".
    if &bs[0..4] == b"LZX\0" {
        detected!("amiga-lzx", Lzx, "Amiga LZX");
    }
    // StuffIt: classic "SIT!" or SIT5 "StuffIt".
    if &bs[0..4] == b"SIT!" || &bs[0..7] == b"StuffIt" {
        detected!("sit", Sit, "StuffIt");
    }

    // Tar: "ustar\0" or "ustar " magic at offset 257 of the first block.
    if &bs[257..262] == b"ustar" {
        detected!("tar", Tar, "tar");
    }

    // ISO 9660: PVD at LBA 16 (byte 32768) starts with type=0x01,
    // standard identifier "CD001", version=0x01. The PVD is the
    // canonical entry point regardless of Joliet / Rock Ridge / boot
    // record presence.
    if dev.total_size() >= 32768 + 7 {
        let mut iso = [0u8; 7];
        dev.read_at(32768, &mut iso)?;
        if &iso[1..6] == b"CD001" {
            detected!("iso9660", Iso9660, "ISO 9660");
        }
    }

    // APFS: container superblock magic "NXSB" at offset 32 of block 0.
    if &bs[32..36] == b"NXSB" {
        detected!("apfs", Apfs, "APFS");
    }

    // ext superblock starts at byte 1024; s_magic (0xEF53) is at offset 56.
    let mut sb_magic = [0u8; 2];
    if dev.total_size() >= 1024 + 56 + 2 {
        dev.read_at(1024 + 56, &mut sb_magic)?;
        if sb_magic == [0x53, 0xEF] {
            detected!("ext", Ext, "ext2/3/4");
        }
    }

    // HFS+ / HFSX volume header sig at byte 1024.
    let mut hfs_sig = [0u8; 2];
    if dev.total_size() >= 1024 + 2 {
        dev.read_at(1024, &mut hfs_sig)?;
        if &hfs_sig == b"H+" || &hfs_sig == b"HX" {
            detected!("hfs-plus", HfsPlus, "HFS+");
        }
        // Classic HFS Master Directory Block signature `BD` at byte 1024.
        if &hfs_sig == b"BD" {
            detected!("hfs", Hfs, "HFS");
        }
    }

    // F2FS: 32-bit LE magic 0xF2F52010 at offset 1024 (primary) or
    // 1024 + 0x1000 (backup). Check both copies before giving up.
    let mut f2_magic = [0u8; 4];
    if dev.total_size() >= 1024 + 0x1000 + 4 {
        dev.read_at(1024, &mut f2_magic)?;
        if u32::from_le_bytes(f2_magic) == 0xF2F5_2010 {
            detected!("f2fs", F2fs, "F2FS");
        }
        dev.read_at(1024 + 0x1000, &mut f2_magic)?;
        if u32::from_le_bytes(f2_magic) == 0xF2F5_2010 {
            detected!("f2fs", F2fs, "F2FS");
        }
    }

    // SEA ARC: no string magic — first byte 0x1A then a method byte in
    // 1..=11. Heuristic, so it is checked last to avoid shadowing a real
    // filesystem whose sector 0 happens to start with 0x1A.
    if bs[0] == 0x1A && (1..=11).contains(&bs[1]) {
        detected!("arc", Arc, "SEA ARC");
    }

    Err(crate::Error::InvalidImage(
        "inspect: no recognised filesystem or archive on this image".into(),
    ))
}

/// A unified read-side handle. Hides whether the underlying filesystem
/// is ext, FAT32, tar, XFS, exFAT, HFS+, APFS, or any of the other
/// backends.
///
/// Most external callers should prefer [`open`] (returns a
/// `Box<dyn Filesystem>`) and [`summary`] (returns a [`Summary`]) —
/// those don't ask you to know the variant list. `AnyFs` is the
/// in-crate dispatch helper they build on; matching on its variants
/// is fine in-crate but isn't a stable surface.
pub enum AnyFs {
    #[cfg(feature = "ext")]
    Ext(Box<Ext>),
    #[cfg(feature = "fat")]
    Fat32(Box<Fat32>),
    /// Tar archive — read-only via this handle.
    #[cfg(feature = "tar")]
    Tar(Box<Tar>),
    /// XFS — read-only (shortform dirs + extent-format files).
    #[cfg(feature = "xfs")]
    Xfs(Box<Xfs>),
    /// exFAT — read-only.
    #[cfg(feature = "exfat")]
    Exfat(Box<Exfat>),
    /// HFS+ — read-only.
    #[cfg(feature = "hfs-plus")]
    HfsPlus(Box<HfsPlus>),
    #[cfg(feature = "hfs")]
    Hfs(Box<Hfs>),
    /// Amiga OFS/FFS (AFFS) — read-only.
    #[cfg(feature = "affs")]
    Affs(Box<Affs>),
    /// littlefs — read + write (metadata pairs + CTZ skip-lists).
    #[cfg(feature = "littlefs")]
    LittleFs(Box<LittleFs>),
    /// APFS — read-only; single-leaf trees only.
    #[cfg(feature = "apfs")]
    Apfs(Box<Apfs>),
    /// NTFS — read + write (MFT, attributes, `$DATA` + ADS, indexes).
    #[cfg(feature = "ntfs")]
    Ntfs(Box<Ntfs>),
    /// F2FS — read + write (build-once: a re-opened image is read-only).
    #[cfg(feature = "f2fs")]
    F2fs(Box<F2fs>),
    /// SquashFS — read + write via `repack` (compressed, repack-only).
    #[cfg(feature = "squashfs")]
    Squashfs(Box<Squashfs>),
    /// ISO 9660 — read-only (PVD + Joliet + Rock Ridge + El Torito).
    #[cfg(feature = "iso9660")]
    Iso9660(Box<crate::fs::iso9660::Iso9660>),
    /// GRF — Ragnarok Online archive; full read/write/add/rm.
    #[cfg(feature = "grf")]
    Grf(Box<crate::fs::grf::Grf>),
    /// Any archive-core backend (zip / cpio / ar / 7z / …), held behind
    /// the [`crate::fs::Filesystem`] trait with its kind tag and name.
    /// The 10 archive formats share one variant since they dispatch
    /// uniformly through the trait.
    #[cfg(feature = "archive")]
    Archive(Box<dyn crate::fs::Filesystem>, FsKind, &'static str),
    /// In-memory ramfs — never produced by [`detect_fs`]; built explicitly
    /// via [`AnyFs::new_ramfs`] / [`AnyFs::new_ramfs_from`].
    #[cfg(feature = "ramfs")]
    Ramfs(Box<Ramfs>),
}

impl AnyFs {
    /// A fresh, empty in-memory ramfs wrapped as an `AnyFs`.
    #[cfg(feature = "ramfs")]
    #[must_use]
    pub fn new_ramfs() -> Self {
        Self::Ramfs(Box::default())
    }

    /// A ramfs pre-populated from `source` (a host dir / image / tar), built
    /// through the generic repack sink so symlinks, devices and xattrs carry
    /// over. The `dev` is the ramfs's ignored device.
    #[cfg(feature = "ramfs")]
    pub fn new_ramfs_from(
        dev: &mut dyn BlockDevice,
        source: &crate::repack::Source,
    ) -> Result<Self> {
        let mut fs = Ramfs::new();
        crate::repack::populate_fs_from_source_dyn(dev, &mut fs, source)?;
        Ok(Self::Ramfs(Box::new(fs)))
    }

    /// Open `dev`, picking the backend automatically.
    pub fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        let kind = detect_fs(dev)?;
        Self::open_kind(dev, kind)
    }

    /// [`Self::open`] for an already-probed `kind` — the shared dispatch
    /// table behind `open` and [`Self::open_writable`].
    fn open_kind(dev: &mut dyn BlockDevice, kind: FsKind) -> Result<Self> {
        match kind {
            #[cfg(feature = "ramfs")]
            FsKind::Ramfs => {
                // (`dev` is otherwise unused in a ramfs-only build.)
                let _ = &dev;
                Err(crate::Error::Unsupported(
                    "ramfs has no on-disk form; construct it with AnyFs::new_ramfs()".into(),
                ))
            }
            #[cfg(feature = "ext")]
            FsKind::Ext => Ok(Self::Ext(Box::new(Ext::open(dev)?))),
            #[cfg(feature = "fat")]
            FsKind::Fat32 => Ok(Self::Fat32(Box::new(Fat32::open(dev)?))),
            #[cfg(feature = "tar")]
            FsKind::Tar => Ok(Self::Tar(Box::new(Tar::open(dev)?))),
            #[cfg(feature = "xfs")]
            FsKind::Xfs => Ok(Self::Xfs(Box::new(Xfs::open(dev)?))),
            #[cfg(feature = "exfat")]
            FsKind::Exfat => Ok(Self::Exfat(Box::new(Exfat::open(dev)?))),
            #[cfg(feature = "hfs-plus")]
            FsKind::HfsPlus => Ok(Self::HfsPlus(Box::new(HfsPlus::open(dev)?))),
            #[cfg(feature = "hfs")]
            FsKind::Hfs => Ok(Self::Hfs(Box::new(Hfs::open(dev)?))),
            #[cfg(feature = "affs")]
            FsKind::Affs => Ok(Self::Affs(Box::new(Affs::open(dev)?))),
            #[cfg(feature = "littlefs")]
            FsKind::LittleFs => Ok(Self::LittleFs(Box::new(LittleFs::open(dev)?))),
            #[cfg(feature = "apfs")]
            FsKind::Apfs => Ok(Self::Apfs(Box::new(Apfs::open(dev)?))),
            #[cfg(feature = "ntfs")]
            FsKind::Ntfs => Ok(Self::Ntfs(Box::new(Ntfs::open(dev)?))),
            #[cfg(feature = "f2fs")]
            FsKind::F2fs => Ok(Self::F2fs(Box::new(F2fs::open(dev)?))),
            #[cfg(feature = "squashfs")]
            FsKind::Squashfs => Ok(Self::Squashfs(Box::new(Squashfs::open(dev)?))),
            #[cfg(feature = "iso9660")]
            FsKind::Iso9660 => Ok(Self::Iso9660(Box::new(crate::fs::iso9660::Iso9660::open(
                dev,
            )?))),
            #[cfg(feature = "grf")]
            FsKind::Grf => Ok(Self::Grf(Box::new(crate::fs::grf::Grf::open_dev(dev)?))),
            #[cfg(feature = "archive")]
            FsKind::Zip => Ok(Self::Archive(
                Box::new(ZipFs::open(dev)?),
                FsKind::Zip,
                "zip",
            )),
            #[cfg(feature = "archive")]
            FsKind::Cpio => Ok(Self::Archive(
                Box::new(CpioFs::open(dev)?),
                FsKind::Cpio,
                "cpio",
            )),
            #[cfg(feature = "archive")]
            FsKind::Ar => Ok(Self::Archive(Box::new(ArFs::open(dev)?), FsKind::Ar, "ar")),
            #[cfg(feature = "sevenz")]
            FsKind::SevenZ => Ok(Self::Archive(
                Box::new(SevenZFs::open(dev)?),
                FsKind::SevenZ,
                "7z",
            )),
            #[cfg(feature = "rar")]
            FsKind::Rar => Ok(Self::Archive(
                Box::new(RarFs::open(dev)?),
                FsKind::Rar,
                "rar",
            )),
            #[cfg(feature = "arc")]
            FsKind::Arc => Ok(Self::Archive(
                Box::new(ArcFs::open(dev)?),
                FsKind::Arc,
                "arc",
            )),
            #[cfg(feature = "lha")]
            FsKind::Lha => Ok(Self::Archive(
                Box::new(LhaFs::open(dev)?),
                FsKind::Lha,
                "lha",
            )),
            #[cfg(feature = "amiga-lzx")]
            FsKind::Lzx => Ok(Self::Archive(
                Box::new(LzxFs::open(dev)?),
                FsKind::Lzx,
                "lzx",
            )),
            #[cfg(feature = "cab")]
            FsKind::Cab => Ok(Self::Archive(
                Box::new(CabFs::open(dev)?),
                FsKind::Cab,
                "cab",
            )),
            #[cfg(feature = "sit")]
            FsKind::Sit => Ok(Self::Archive(
                Box::new(SitFs::open(dev)?),
                FsKind::Sit,
                "sit",
            )),
        }
    }

    /// Like [`Self::open`], but for callers that intend to mutate
    /// the filesystem in place (`add` / `rm` / `shell`). APFS routes
    /// to [`Apfs::open_writable`] so the new checkpoint COW pathway
    /// is reachable; every other backend's writer is already alive
    /// after a plain `open`, so they share the same dispatch table.
    ///
    /// Read-only callers (`ls`, `cat`, `info`, `analyze`) should keep
    /// using [`Self::open`] — it's cheaper for APFS (no spaceman
    /// re-parse, no Write-state scaffolding) and uniform across
    /// backends.
    pub fn open_writable(dev: &mut dyn BlockDevice) -> Result<Self> {
        // An `if` chain rather than a `match` with a `_ => open` arm: in a
        // build whose only backends are the three below, that arm would be
        // unreachable and warn.
        let kind = detect_fs(dev)?;
        #[cfg(feature = "apfs")]
        if kind == FsKind::Apfs {
            return Ok(Self::Apfs(Box::new(Apfs::open_writable(dev)?)));
        }
        // Classic HFS opens read-only by default; the in-place writer is a
        // distinct path that loads the catalog into a mutable form.
        #[cfg(feature = "hfs")]
        if kind == FsKind::Hfs {
            return Ok(Self::Hfs(Box::new(crate::fs::hfs::Hfs::open_writable(
                dev,
            )?)));
        }
        // AFFS, like classic HFS, opens read-only by default; the in-place
        // writer loads the whole tree into a mutable model.
        #[cfg(feature = "affs")]
        if kind == FsKind::Affs {
            return Ok(Self::Affs(Box::new(Affs::open_writable(dev)?)));
        }
        // Every other backend's open() already returns a mutable
        // handle (ext journals, FAT/exFAT/NTFS rewrite, …), so
        // just defer to the existing dispatch.
        Self::open_kind(dev, kind)
    }

    /// Which filesystem this handle is talking to.
    pub fn kind(&self) -> FsKind {
        match self {
            #[cfg(feature = "ext")]
            Self::Ext(_) => FsKind::Ext,
            #[cfg(feature = "fat")]
            Self::Fat32(_) => FsKind::Fat32,
            #[cfg(feature = "tar")]
            Self::Tar(_) => FsKind::Tar,
            #[cfg(feature = "xfs")]
            Self::Xfs(_) => FsKind::Xfs,
            #[cfg(feature = "exfat")]
            Self::Exfat(_) => FsKind::Exfat,
            #[cfg(feature = "hfs-plus")]
            Self::HfsPlus(_) => FsKind::HfsPlus,
            #[cfg(feature = "hfs")]
            Self::Hfs(_) => FsKind::Hfs,
            #[cfg(feature = "affs")]
            Self::Affs(_) => FsKind::Affs,
            #[cfg(feature = "littlefs")]
            Self::LittleFs(_) => FsKind::LittleFs,
            #[cfg(feature = "apfs")]
            Self::Apfs(_) => FsKind::Apfs,
            #[cfg(feature = "ntfs")]
            Self::Ntfs(_) => FsKind::Ntfs,
            #[cfg(feature = "f2fs")]
            Self::F2fs(_) => FsKind::F2fs,
            #[cfg(feature = "squashfs")]
            Self::Squashfs(_) => FsKind::Squashfs,
            #[cfg(feature = "iso9660")]
            Self::Iso9660(_) => FsKind::Iso9660,
            #[cfg(feature = "grf")]
            Self::Grf(_) => FsKind::Grf,
            #[cfg(feature = "archive")]
            Self::Archive(_, kind, _) => *kind,
            #[cfg(feature = "ramfs")]
            Self::Ramfs(_) => FsKind::Ramfs,
        }
    }

    /// List the entries of a directory by absolute path. Takes `&mut self`
    /// because some read-only backends (NTFS, F2FS) maintain cached state
    /// (run-list bootstrap, checkpoint selection) behind their list path.
    pub fn list(&mut self, dev: &mut dyn BlockDevice, path: &str) -> Result<Vec<DirEntry>> {
        match self {
            #[cfg(feature = "ext")]
            Self::Ext(ext) => {
                let ino = ext.path_to_inode(dev, path)?;
                ext.list_inode(dev, ino)
            }
            #[cfg(feature = "fat")]
            Self::Fat32(fat) => fat.list_path(dev, path),
            #[cfg(feature = "tar")]
            Self::Tar(tar) => tar.list_path(dev, path),
            #[cfg(feature = "xfs")]
            Self::Xfs(xfs) => xfs.list_path(dev, path),
            #[cfg(feature = "exfat")]
            Self::Exfat(exfat) => exfat.list_path(dev, path),
            #[cfg(feature = "hfs-plus")]
            Self::HfsPlus(hfs) => hfs.list_path(dev, path),
            // Classic HFS and AFFS list from their in-memory catalogue and
            // never touch `dev`; the `let _ = &dev` keeps the parameter used
            // in a build where they are the only backends.
            #[cfg(feature = "hfs")]
            Self::Hfs(hfs) => {
                let _ = &dev;
                hfs.list_path(path)
            }
            #[cfg(feature = "affs")]
            Self::Affs(affs) => {
                let _ = &dev;
                affs.list_path(path)
            }
            #[cfg(feature = "littlefs")]
            Self::LittleFs(lfs) => {
                use crate::fs::Filesystem;
                lfs.list(dev, std::path::Path::new(path))
            }
            #[cfg(feature = "apfs")]
            Self::Apfs(apfs) => apfs.list_path(dev, path),
            #[cfg(feature = "ntfs")]
            Self::Ntfs(ntfs) => ntfs.list_path(dev, path),
            #[cfg(feature = "f2fs")]
            Self::F2fs(f2) => f2.list_path(dev, path),
            #[cfg(feature = "squashfs")]
            Self::Squashfs(sq) => sq.list_path(dev, path),
            #[cfg(feature = "iso9660")]
            Self::Iso9660(iso) => iso.list_path(dev, path),
            #[cfg(feature = "grf")]
            Self::Grf(grf) => {
                use crate::fs::Filesystem;
                grf.list(dev, std::path::Path::new(path))
            }
            #[cfg(feature = "archive")]
            Self::Archive(fs, _, _) => fs.list(dev, std::path::Path::new(path)),
            #[cfg(feature = "ramfs")]
            Self::Ramfs(r) => {
                use crate::fs::Filesystem;
                r.list(dev, std::path::Path::new(path))
            }
        }
    }

    /// Recursive sum of regular-file sizes across the whole FS.
    /// Delegates to the inner backend's
    /// [`crate::fs::Filesystem::total_file_bytes`] implementation,
    /// which itself is a [`Self::list`]-driven walk.
    pub fn total_file_bytes(&mut self, dev: &mut dyn BlockDevice) -> Result<u64> {
        self.as_filesystem_dyn(|fs| fs.total_file_bytes(dev))
    }

    /// Filesystem-level capacity stats — delegates to the inner backend's
    /// [`crate::fs::Filesystem::statfs`]. Backends without a real superblock
    /// answer return [`crate::fs::StatFs::default`] (zero counts), which is
    /// what `fstool info` / the shell `df` surface verbatim.
    pub fn statfs(&mut self, dev: &mut dyn BlockDevice) -> Result<crate::fs::StatFs> {
        self.as_filesystem_dyn(|fs| fs.statfs(dev))
    }

    /// Full attributes for `path` — delegates to the inner backend's
    /// [`crate::fs::Filesystem::getattr`]. Used by the repack walker to
    /// read source metadata uniformly.
    pub fn getattr(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
    ) -> Result<crate::fs::FileAttrs> {
        self.as_filesystem_dyn(|fs| fs.getattr(dev, path))
    }

    /// Extended attributes for `path` — delegates to the inner backend's
    /// [`crate::fs::Filesystem::list_xattrs`] (empty for backends without
    /// xattr storage).
    pub fn list_xattrs(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
    ) -> Result<Vec<crate::fs::XattrPair>> {
        self.as_filesystem_dyn(|fs| fs.list_xattrs(dev, path))
    }

    /// Read a symbolic link's target as a UTF-8 string. Delegates to
    /// the inner backend's [`crate::fs::Filesystem::read_symlink`].
    /// Returns `Unsupported` for filesystems that don't carry symlinks
    /// (FAT32, exFAT) or whose symlink support isn't wired through
    /// the trait yet (APFS, F2FS, NTFS, ISO 9660 Rock Ridge).
    pub fn read_symlink(&mut self, dev: &mut dyn BlockDevice, path: &str) -> Result<String> {
        let p = std::path::Path::new(path);
        let target = self.as_filesystem_dyn(|fs| fs.read_symlink(dev, p))?;
        Ok(target.to_string_lossy().into_owned())
    }

    /// Stream a regular file's bytes into `out`. The file is read in
    /// 64 KiB chunks; nothing larger than that buffer is ever resident.
    /// Takes `&mut self` for the same reason as [`AnyFs::list`].
    pub fn copy_file_to(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        out: &mut dyn std::io::Write,
    ) -> Result<u64> {
        let mut buf = [0u8; 64 * 1024];
        match self {
            #[cfg(feature = "ext")]
            Self::Ext(ext) => {
                let ino = ext.path_to_inode(dev, path)?;
                let mut r = ext.open_file_reader(dev, ino)?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "fat")]
            Self::Fat32(fat) => {
                let mut r = fat.open_file_reader(dev, path)?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "tar")]
            Self::Tar(tar) => {
                let mut r = tar.open_file_reader(dev, path)?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "xfs")]
            Self::Xfs(xfs) => {
                let mut r = xfs.open_file_reader(dev, path)?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "exfat")]
            Self::Exfat(exfat) => {
                let mut r = exfat.open_file_reader(dev, path)?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "hfs")]
            Self::Hfs(hfs) => {
                let mut r = hfs.open_file_reader(dev, path)?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "affs")]
            Self::Affs(affs) => {
                let mut r = affs.open_file_reader(dev, path)?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "littlefs")]
            Self::LittleFs(lfs) => {
                use crate::fs::Filesystem;
                let mut r = lfs.read_file(dev, std::path::Path::new(path))?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "hfs-plus")]
            Self::HfsPlus(hfs) => {
                let mut r = hfs.open_file_reader(dev, path)?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "apfs")]
            Self::Apfs(apfs) => {
                let mut r = apfs.open_file_reader(dev, path)?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "ntfs")]
            Self::Ntfs(ntfs) => {
                let mut r = ntfs.open_file_reader(dev, path)?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "f2fs")]
            Self::F2fs(f2) => {
                let mut r = f2.open_file_reader(dev, path)?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "squashfs")]
            Self::Squashfs(sq) => {
                let mut r = sq.open_file_reader(dev, path)?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "iso9660")]
            Self::Iso9660(iso) => {
                let mut r = iso.open_file_reader(dev, path)?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "grf")]
            Self::Grf(grf) => {
                // GRF entries are full-buffer inflated; stream the
                // bytes from a cursor over the inflated body.
                let key = path.trim_start_matches('/').to_string();
                let entry = grf.entries.get(&key).cloned().ok_or_else(|| {
                    crate::Error::InvalidArgument(format!("grf: no entry at {key:?}"))
                })?;
                let bytes = grf.read_entry(dev, &entry)?;
                let mut r = std::io::Cursor::new(bytes);
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "archive")]
            Self::Archive(fs, _, _) => {
                let mut r = fs.read_file(dev, std::path::Path::new(path))?;
                pump(&mut r, out, &mut buf)
            }
            #[cfg(feature = "ramfs")]
            Self::Ramfs(rfs) => {
                use crate::fs::Filesystem;
                let mut r = rfs.read_file(dev, std::path::Path::new(path))?;
                pump(&mut r, out, &mut buf)
            }
        }
    }

    /// Open a borrowed streaming reader over a regular file's body.
    /// Pull-based counterpart to [`Self::copy_file_to`] — the repack
    /// walker uses it to hand a `&mut dyn Read` straight to a
    /// destination's `create_file_streaming` without a tempfile. The
    /// returned reader borrows both `self` and `dev` for `'a`.
    ///
    /// (An inline match rather than the `as_filesystem_dyn` helper: the
    /// closure-based helper fixes the return type's lifetime too early
    /// to hand back a reader borrowing `dev`.)
    pub fn open_body_reader<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &str,
    ) -> Result<Box<dyn std::io::Read + 'a>> {
        match self {
            #[cfg(feature = "ext")]
            Self::Ext(ext) => {
                let ino = ext.path_to_inode(dev, path)?;
                Ok(Box::new(ext.open_file_reader(dev, ino)?))
            }
            #[cfg(feature = "fat")]
            Self::Fat32(fat) => Ok(Box::new(fat.open_file_reader(dev, path)?)),
            #[cfg(feature = "tar")]
            Self::Tar(tar) => Ok(Box::new(tar.open_file_reader(dev, path)?)),
            #[cfg(feature = "xfs")]
            Self::Xfs(xfs) => Ok(Box::new(xfs.open_file_reader(dev, path)?)),
            #[cfg(feature = "exfat")]
            Self::Exfat(exfat) => Ok(Box::new(exfat.open_file_reader(dev, path)?)),
            #[cfg(feature = "hfs-plus")]
            Self::HfsPlus(hfs) => Ok(Box::new(hfs.open_file_reader(dev, path)?)),
            #[cfg(feature = "hfs")]
            Self::Hfs(hfs) => Ok(Box::new(hfs.open_file_reader(dev, path)?)),
            #[cfg(feature = "affs")]
            Self::Affs(affs) => Ok(Box::new(affs.open_file_reader(dev, path)?)),
            #[cfg(feature = "littlefs")]
            Self::LittleFs(lfs) => {
                use crate::fs::Filesystem;
                lfs.read_file(dev, std::path::Path::new(path))
            }
            #[cfg(feature = "apfs")]
            Self::Apfs(apfs) => Ok(Box::new(apfs.open_file_reader(dev, path)?)),
            #[cfg(feature = "ntfs")]
            Self::Ntfs(ntfs) => Ok(Box::new(ntfs.open_file_reader(dev, path)?)),
            #[cfg(feature = "f2fs")]
            Self::F2fs(f2) => Ok(Box::new(f2.open_file_reader(dev, path)?)),
            #[cfg(feature = "squashfs")]
            Self::Squashfs(sq) => Ok(Box::new(sq.open_file_reader(dev, path)?)),
            #[cfg(feature = "iso9660")]
            Self::Iso9660(iso) => Ok(Box::new(iso.open_file_reader(dev, path)?)),
            #[cfg(feature = "grf")]
            Self::Grf(grf) => {
                let key = path.trim_start_matches('/').to_string();
                let entry = grf.entries.get(&key).cloned().ok_or_else(|| {
                    crate::Error::InvalidArgument(format!("grf: no entry at {key:?}"))
                })?;
                let bytes = grf.read_entry(dev, &entry)?;
                Ok(Box::new(std::io::Cursor::new(bytes)))
            }
            #[cfg(feature = "archive")]
            Self::Archive(fs, _, _) => fs.read_file(dev, std::path::Path::new(path)),
            #[cfg(feature = "ramfs")]
            Self::Ramfs(r) => {
                use crate::fs::Filesystem;
                r.read_file(dev, std::path::Path::new(path))
            }
        }
    }

    /// Open a streaming reader over a file's **resource fork**. Only classic
    /// HFS carries resource forks in fstool today; every other filesystem
    /// returns [`crate::Error::Unsupported`].
    pub fn open_resource_fork_reader<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &str,
    ) -> Result<Box<dyn std::io::Read + 'a>> {
        #[cfg(not(any(feature = "hfs", feature = "hfs-plus")))]
        let _ = (dev, path);
        match self {
            #[cfg(feature = "hfs")]
            Self::Hfs(hfs) => Ok(Box::new(hfs.open_resource_fork_reader(dev, path)?)),
            #[cfg(feature = "hfs-plus")]
            Self::HfsPlus(hfs) => Ok(Box::new(hfs.open_resource_fork_reader(dev, path)?)),
            // Every backend other than HFS / HFS+ — the arm is compiled out
            // when none of those is present, since it would be unreachable.
            #[cfg(any(
                feature = "ext",
                feature = "fat",
                feature = "tar",
                feature = "xfs",
                feature = "exfat",
                feature = "affs",
                feature = "littlefs",
                feature = "apfs",
                feature = "ntfs",
                feature = "f2fs",
                feature = "squashfs",
                feature = "iso9660",
                feature = "grf",
                feature = "archive",
                feature = "ramfs",
            ))]
            _ => Err(crate::Error::Unsupported(
                "resource forks are only supported on HFS / HFS+".into(),
            )),
        }
    }

    /// Read a file's whole resource fork into memory (capped at 64 MiB — larger
    /// than any classic resource fork). Convenience for the resource-map parser.
    pub fn read_resource_fork(&mut self, dev: &mut dyn BlockDevice, path: &str) -> Result<Vec<u8>> {
        use std::io::Read;
        const CAP: u64 = 64 * 1024 * 1024;
        let r = self.open_resource_fork_reader(dev, path)?;
        let mut buf = Vec::new();
        r.take(CAP).read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Add a regular file at `dest_path`, populated from a host file.
    /// Parent directories must already exist. Dispatches through the
    /// generic [`crate::fs::Filesystem`] trait. Filesystems whose
    /// reader can't be re-opened as a writer (most non-ext/non-FAT)
    /// will error with a trait-specific message.
    pub fn add_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        dest_path: &str,
        host_src: &Path,
    ) -> Result<()> {
        self.require_mutable("add")?;
        let meta = std::fs::symlink_metadata(host_src)?;
        // Preserve the host file's mode/owner/timestamps, matching the
        // `build`/`create` path — not just the mode.
        let fmeta = crate::repack::host_meta_to_fs(&meta);
        let dest = std::path::Path::new(dest_path);
        let src = crate::fs::FileSource::HostPath(host_src.to_path_buf());
        self.as_filesystem_dyn(move |fs| fs.create_file(dev, dest, src, fmeta))
    }

    /// Recursively add a host directory tree at `dest_path`. The
    /// destination's parent must exist; the leaf is created. Dispatches
    /// through the [`crate::fs::Filesystem`] trait.
    pub fn add_dir_tree(
        &mut self,
        dev: &mut dyn BlockDevice,
        dest_path: &str,
        host_src: &Path,
    ) -> Result<()> {
        self.require_mutable("add")?;
        let meta = std::fs::symlink_metadata(host_src)?;
        // Preserve the host directory's mode/owner/timestamps (the tree's
        // children are handled by the recursive populate below, which already
        // carries host metadata).
        let fmeta = crate::repack::host_meta_to_fs(&meta);
        let dest = std::path::Path::new(dest_path);
        self.as_filesystem_dyn(|fs| fs.create_dir(dev, dest, fmeta))?;
        // Walk the host source recursively through the trait. Errors
        // from each entry propagate immediately.
        let source = crate::repack::Source::HostDir(host_src.to_path_buf());
        self.populate_from_source_at(dev, dest_path, &source)
    }

    /// Create an empty directory at `path` with mode 0o755 (umask 022
    /// over 0o777). Dispatches through the trait.
    pub fn mkdir(&mut self, dev: &mut dyn BlockDevice, path: &str) -> Result<()> {
        self.require_mutable("mkdir")?;
        let fmeta = crate::fs::FileMeta {
            mode: 0o755,
            ..crate::fs::FileMeta::default()
        };
        let p = std::path::Path::new(path);
        self.as_filesystem_dyn(|fs| fs.create_dir(dev, p, fmeta))
    }

    /// Remove an entry at `path` — a file, symlink, device, or empty
    /// directory. Non-empty directories are rejected. Dispatches
    /// through the trait.
    pub fn remove(&mut self, dev: &mut dyn BlockDevice, path: &str) -> Result<()> {
        self.require_mutable("rm")?;
        let p = std::path::Path::new(path);
        self.as_filesystem_dyn(|fs| fs.remove(dev, p))
    }

    /// Whether this filesystem can mutate an already-flushed image
    /// (`add` / `rm` against an existing on-disk FS). Convenience
    /// shortcut for `mutation_capability() == Mutable`. Callers who
    /// need to distinguish *why* a filesystem isn't mutable should
    /// use [`Self::mutation_capability`] instead.
    pub fn supports_mutation(&self) -> bool {
        self.mutation_capability().supports_add_remove()
    }

    /// How this filesystem can be mutated. Delegates to the inner
    /// [`crate::fs::Filesystem::mutation_capability`]. Tar reports
    /// `Streaming`; ISO 9660 and SquashFS report `Immutable`;
    /// everything else (including APFS / exFAT whose writers aren't
    /// implemented yet — those return `Unsupported` per-call from
    /// individual methods) reports `Mutable`.
    /// How the inner filesystem addresses files on read — the forward-scan
    /// flag (see [`crate::fs::AccessMode`]). Sequential archives report
    /// [`Sequential`](crate::fs::AccessMode::Sequential); everything else
    /// reports [`RandomAccess`](crate::fs::AccessMode::RandomAccess).
    pub fn access_mode(&self) -> crate::fs::AccessMode {
        match self {
            #[cfg(feature = "ext")]
            Self::Ext(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "fat")]
            Self::Fat32(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "hfs-plus")]
            Self::HfsPlus(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "hfs")]
            Self::Hfs(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "affs")]
            Self::Affs(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "littlefs")]
            Self::LittleFs(l) => crate::fs::Filesystem::access_mode(l.as_ref()),
            #[cfg(feature = "ntfs")]
            Self::Ntfs(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "f2fs")]
            Self::F2fs(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "squashfs")]
            Self::Squashfs(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "xfs")]
            Self::Xfs(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "iso9660")]
            Self::Iso9660(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "tar")]
            Self::Tar(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "apfs")]
            Self::Apfs(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "exfat")]
            Self::Exfat(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "grf")]
            Self::Grf(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
            #[cfg(feature = "archive")]
            Self::Archive(fs, _, _) => crate::fs::Filesystem::access_mode(fs.as_ref()),
            #[cfg(feature = "ramfs")]
            Self::Ramfs(f) => crate::fs::Filesystem::access_mode(f.as_ref()),
        }
    }

    pub fn mutation_capability(&self) -> crate::fs::MutationCapability {
        match self {
            #[cfg(feature = "ext")]
            Self::Ext(ext) => crate::fs::Filesystem::mutation_capability(ext.as_ref()),
            #[cfg(feature = "fat")]
            Self::Fat32(fat) => crate::fs::Filesystem::mutation_capability(fat.as_ref()),
            #[cfg(feature = "hfs-plus")]
            Self::HfsPlus(h) => crate::fs::Filesystem::mutation_capability(h.as_ref()),
            #[cfg(feature = "hfs")]
            Self::Hfs(h) => crate::fs::Filesystem::mutation_capability(h.as_ref()),
            #[cfg(feature = "affs")]
            Self::Affs(a) => crate::fs::Filesystem::mutation_capability(a.as_ref()),
            #[cfg(feature = "littlefs")]
            Self::LittleFs(l) => crate::fs::Filesystem::mutation_capability(l.as_ref()),
            #[cfg(feature = "ntfs")]
            Self::Ntfs(n) => crate::fs::Filesystem::mutation_capability(n.as_ref()),
            #[cfg(feature = "f2fs")]
            Self::F2fs(fs2) => crate::fs::Filesystem::mutation_capability(fs2.as_ref()),
            #[cfg(feature = "squashfs")]
            Self::Squashfs(sq) => crate::fs::Filesystem::mutation_capability(sq.as_ref()),
            #[cfg(feature = "xfs")]
            Self::Xfs(x) => crate::fs::Filesystem::mutation_capability(x.as_ref()),
            #[cfg(feature = "iso9660")]
            Self::Iso9660(iso) => crate::fs::Filesystem::mutation_capability(iso.as_ref()),
            #[cfg(feature = "tar")]
            Self::Tar(t) => crate::fs::Filesystem::mutation_capability(t.as_ref()),
            #[cfg(feature = "apfs")]
            Self::Apfs(a) => crate::fs::Filesystem::mutation_capability(a.as_ref()),
            #[cfg(feature = "exfat")]
            Self::Exfat(e) => crate::fs::Filesystem::mutation_capability(e.as_ref()),
            #[cfg(feature = "grf")]
            Self::Grf(g) => crate::fs::Filesystem::mutation_capability(g.as_ref()),
            #[cfg(feature = "archive")]
            Self::Archive(fs, _, _) => crate::fs::Filesystem::mutation_capability(fs.as_ref()),
            #[cfg(feature = "ramfs")]
            Self::Ramfs(r) => crate::fs::Filesystem::mutation_capability(r.as_ref()),
        }
    }

    /// Reflink / clone capability of the inner filesystem. Same shape
    /// as [`Self::mutation_capability`], delegating to
    /// [`crate::fs::Filesystem::clone_capability`]. Backends that
    /// natively share extents return `WholeFile` or `Range`; everything
    /// else reports `None`, in which case [`Self::clone_file`] still
    /// works by byte-copy but [`Self::clone_range`] errors
    /// `Unsupported`.
    pub fn clone_capability(&self) -> crate::fs::CloneCapability {
        match self {
            #[cfg(feature = "ext")]
            Self::Ext(ext) => crate::fs::Filesystem::clone_capability(ext.as_ref()),
            #[cfg(feature = "fat")]
            Self::Fat32(fat) => crate::fs::Filesystem::clone_capability(fat.as_ref()),
            #[cfg(feature = "hfs-plus")]
            Self::HfsPlus(h) => crate::fs::Filesystem::clone_capability(h.as_ref()),
            #[cfg(feature = "hfs")]
            Self::Hfs(h) => crate::fs::Filesystem::clone_capability(h.as_ref()),
            #[cfg(feature = "affs")]
            Self::Affs(a) => crate::fs::Filesystem::clone_capability(a.as_ref()),
            #[cfg(feature = "littlefs")]
            Self::LittleFs(l) => crate::fs::Filesystem::clone_capability(l.as_ref()),
            #[cfg(feature = "ntfs")]
            Self::Ntfs(n) => crate::fs::Filesystem::clone_capability(n.as_ref()),
            #[cfg(feature = "f2fs")]
            Self::F2fs(fs2) => crate::fs::Filesystem::clone_capability(fs2.as_ref()),
            #[cfg(feature = "squashfs")]
            Self::Squashfs(sq) => crate::fs::Filesystem::clone_capability(sq.as_ref()),
            #[cfg(feature = "xfs")]
            Self::Xfs(x) => crate::fs::Filesystem::clone_capability(x.as_ref()),
            #[cfg(feature = "iso9660")]
            Self::Iso9660(iso) => crate::fs::Filesystem::clone_capability(iso.as_ref()),
            #[cfg(feature = "tar")]
            Self::Tar(t) => crate::fs::Filesystem::clone_capability(t.as_ref()),
            #[cfg(feature = "apfs")]
            Self::Apfs(a) => crate::fs::Filesystem::clone_capability(a.as_ref()),
            #[cfg(feature = "exfat")]
            Self::Exfat(e) => crate::fs::Filesystem::clone_capability(e.as_ref()),
            #[cfg(feature = "grf")]
            Self::Grf(g) => crate::fs::Filesystem::clone_capability(g.as_ref()),
            #[cfg(feature = "archive")]
            Self::Archive(fs, _, _) => crate::fs::Filesystem::clone_capability(fs.as_ref()),
            #[cfg(feature = "ramfs")]
            Self::Ramfs(r) => crate::fs::Filesystem::clone_capability(r.as_ref()),
        }
    }

    /// Clone the file at `src` to `dst`. Routes through the underlying
    /// filesystem's [`crate::fs::Filesystem::clone_file`]: reflink-
    /// capable backends share extents, everything else byte-copies.
    /// Guarded by the internal `require_mutable` check so immutable /
    /// streaming backends fail with a typed error up front instead of
    /// erroring deep inside the writer.
    pub fn clone_file(&mut self, dev: &mut dyn BlockDevice, src: &str, dst: &str) -> Result<()> {
        self.require_mutable("clone_file")?;
        let s = std::path::Path::new(src);
        let d = std::path::Path::new(dst);
        self.as_filesystem_dyn(|fs| fs.clone_file(dev, s, d))
    }

    /// Clone an arbitrary byte range. Only reflink-capable backends
    /// implement this; everything else returns `Unsupported`.
    pub fn clone_range(
        &mut self,
        dev: &mut dyn BlockDevice,
        src: &str,
        src_off: u64,
        dst: &str,
        dst_off: u64,
        len: u64,
    ) -> Result<()> {
        self.require_mutable("clone_range")?;
        let s = std::path::Path::new(src);
        let d = std::path::Path::new(dst);
        self.as_filesystem_dyn(|fs| fs.clone_range(dev, s, src_off, d, dst_off, len))
    }

    /// Internal guard: emit the right typed error variant for the
    /// failure mode of a non-mutable filesystem before dispatching a
    /// write call. APFS/exFAT — whose writers simply aren't wired
    /// yet — report `Mutable`, so they fall through this guard and
    /// the underlying create_* method's own `Unsupported("…not yet
    /// implemented")` surfaces instead.
    fn require_mutable(&self, op: &'static str) -> Result<()> {
        use crate::fs::MutationCapability;
        match self.mutation_capability() {
            // Mutable and WholeFileOnly both satisfy `create_file` /
            // `remove`; the difference between them matters only for
            // partial-write APIs (none today).
            MutationCapability::Mutable | MutationCapability::WholeFileOnly => Ok(()),
            MutationCapability::Streaming => Err(crate::Error::Streaming {
                kind: self.kind_string(),
                op,
            }),
            MutationCapability::Immutable => Err(crate::Error::Immutable {
                kind: self.kind_string(),
                op,
            }),
        }
    }

    /// Dispatch a closure to whichever inner filesystem implements
    /// [`crate::fs::Filesystem`]. Centralises the per-variant `match`
    /// so callers like [`Self::add_file`] / [`Self::mkdir`] /
    /// [`Self::remove`] aren't 10-arm long.
    pub(crate) fn as_filesystem_dyn<R>(
        &mut self,
        f: impl FnOnce(&mut dyn crate::fs::Filesystem) -> Result<R>,
    ) -> Result<R> {
        match self {
            #[cfg(feature = "ext")]
            Self::Ext(ext) => f(ext.as_mut()),
            #[cfg(feature = "fat")]
            Self::Fat32(fat) => f(fat.as_mut()),
            #[cfg(feature = "hfs-plus")]
            Self::HfsPlus(h) => f(h.as_mut()),
            #[cfg(feature = "hfs")]
            Self::Hfs(h) => f(h.as_mut()),
            #[cfg(feature = "affs")]
            Self::Affs(a) => f(a.as_mut()),
            #[cfg(feature = "littlefs")]
            Self::LittleFs(l) => f(l.as_mut()),
            #[cfg(feature = "ntfs")]
            Self::Ntfs(n) => f(n.as_mut()),
            #[cfg(feature = "f2fs")]
            Self::F2fs(fs2) => f(fs2.as_mut()),
            #[cfg(feature = "squashfs")]
            Self::Squashfs(sq) => f(sq.as_mut()),
            #[cfg(feature = "xfs")]
            Self::Xfs(x) => f(x.as_mut()),
            #[cfg(feature = "tar")]
            Self::Tar(t) => f(t.as_mut()),
            #[cfg(feature = "apfs")]
            Self::Apfs(a) => f(a.as_mut()),
            #[cfg(feature = "exfat")]
            Self::Exfat(e) => f(e.as_mut()),
            #[cfg(feature = "iso9660")]
            Self::Iso9660(iso) => f(iso.as_mut()),
            #[cfg(feature = "grf")]
            Self::Grf(g) => f(g.as_mut()),
            #[cfg(feature = "archive")]
            Self::Archive(fs, _, _) => f(fs.as_mut()),
            #[cfg(feature = "ramfs")]
            Self::Ramfs(r) => f(r.as_mut()),
        }
    }

    /// Walk the file tree under `src` into `at_path` on this FS via the
    /// generic trait. Used by `add_dir_tree` after the leaf dir has been
    /// created.
    fn populate_from_source_at(
        &mut self,
        dev: &mut dyn BlockDevice,
        at_path: &str,
        src: &crate::repack::Source,
    ) -> Result<()> {
        let base = at_path.trim_end_matches('/').to_string();
        if base.is_empty() {
            return self
                .as_filesystem_dyn(|fs| crate::repack::populate_fs_from_source_dyn(dev, fs, src));
        }
        self.as_filesystem_dyn(|fs| {
            crate::repack::populate_fs_from_source_dyn_at(dev, fs, &base, src)
        })
    }

    /// Persist any in-memory metadata changes to the device.
    ///
    /// Delegates straight to each backend's [`crate::fs::Filesystem::flush`]
    /// via the `as_filesystem_dyn` helper — there is exactly one flush
    /// implementation per backend, and this wrapper must never reimplement
    /// the dispatch. A hand-written per-variant `match` here used
    /// to no-op the backends that buffer directory writes in a `DirBatch`
    /// (NTFS / XFS / exFAT) or a catalog (HFS+), so a CLI `put`/`rm` followed
    /// by exit silently dropped the change. Every backend's `flush` is already
    /// a guarded no-op when nothing is pending (a read-only handle has no
    /// writer / `write_state` / dirty flag), so unconditional delegation is
    /// safe for read-only handles and correct for writable ones.
    pub fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        self.as_filesystem_dyn(|fs| fs.flush(dev))
    }

    /// Update metadata (mode / owner / timestamps) on an existing path.
    /// Delegates to each backend's [`crate::fs::Filesystem::set_attrs`];
    /// backends that can't represent a requested field ignore it, and ones
    /// with no mutable-metadata support return `Unsupported`.
    pub fn set_attrs(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &Path,
        attrs: crate::fs::SetAttrs,
    ) -> Result<()> {
        self.require_mutable("chmod")?;
        self.as_filesystem_dyn(|fs| fs.set_attrs(dev, path, attrs))
    }

    /// One-line FS summary, used by `fstool info`'s heading.
    ///
    /// A single exhaustive `match` so the compiler forces every variant to
    /// yield a real label. (This used to be a list of early-`return`s
    /// followed by a `match` whose remaining arms were `unreachable!()` —
    /// add a variant, forget the early-`return`, and it panics at runtime
    /// instead of failing to compile.)
    pub fn kind_string(&self) -> &'static str {
        match self {
            #[cfg(feature = "ext")]
            Self::Ext(ext) => match ext.kind {
                crate::fs::ext::FsKind::Ext2 => "ext2",
                crate::fs::ext::FsKind::Ext3 => "ext3",
                crate::fs::ext::FsKind::Ext4 => "ext4",
            },
            #[cfg(feature = "fat")]
            Self::Fat32(fat) => fat.kind().as_str(),
            #[cfg(feature = "tar")]
            Self::Tar(_) => "tar",
            #[cfg(feature = "xfs")]
            Self::Xfs(_) => "xfs",
            #[cfg(feature = "exfat")]
            Self::Exfat(_) => "exfat",
            #[cfg(feature = "hfs-plus")]
            Self::HfsPlus(_) => "hfs+",
            #[cfg(feature = "hfs")]
            Self::Hfs(_) => "hfs",
            #[cfg(feature = "affs")]
            Self::Affs(_) => "affs",
            #[cfg(feature = "littlefs")]
            Self::LittleFs(_) => "littlefs",
            #[cfg(feature = "apfs")]
            Self::Apfs(_) => "apfs",
            #[cfg(feature = "ntfs")]
            Self::Ntfs(_) => "ntfs",
            #[cfg(feature = "f2fs")]
            Self::F2fs(_) => "f2fs",
            #[cfg(feature = "squashfs")]
            Self::Squashfs(_) => "squashfs",
            #[cfg(feature = "iso9660")]
            Self::Iso9660(_) => "iso9660",
            #[cfg(feature = "grf")]
            Self::Grf(_) => "grf",
            #[cfg(feature = "archive")]
            Self::Archive(_, _, name) => name,
            #[cfg(feature = "ramfs")]
            Self::Ramfs(_) => "ramfs",
        }
    }
}

/// Pump `reader` into `out` through `buf` until EOF, returning total
/// bytes copied. Used by `copy_file_to` for every backend. `W` is
/// `?Sized` so `&mut dyn Write` callers work directly.
fn pump<R: std::io::Read + ?Sized, W: std::io::Write + ?Sized>(
    reader: &mut R,
    out: &mut W,
    buf: &mut [u8],
) -> Result<u64> {
    let mut total = 0u64;
    loop {
        let n = reader.read(buf).map_err(crate::Error::from)?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n]).map_err(crate::Error::from)?;
        total += n as u64;
    }
    Ok(total)
}

/// One-shot helper: open `path` (regular file, block device, or qcow2),
/// identify the filesystem on it, and return the handle.
pub fn open_image_file(path: &Path) -> Result<(Box<dyn BlockDevice>, AnyFs)> {
    let mut dev = crate::block::open_image(path)?;
    let fs = AnyFs::open(dev.as_mut())?;
    Ok((dev, fs))
}

/// Open `dev` as whatever filesystem it contains, returning the result
/// as a `Box<dyn Filesystem>` — the stable external entry point. The
/// concrete backend is hidden; callers interact through the
/// [`crate::fs::Filesystem`] trait (`list`, `read_file`, `create_*`,
/// `remove`, `flush`, `supports_mutation`).
///
/// Read-only filesystems (tar, APFS, exFAT, SquashFS, ISO 9660, etc.)
/// still parse and walk; their write methods return
/// [`crate::Error::Unsupported`] and `supports_mutation()` returns
/// `false`.
pub fn open(dev: &mut dyn BlockDevice) -> Result<Box<dyn crate::fs::Filesystem>> {
    Ok(AnyFs::open(dev)?.into_dyn_filesystem())
}

/// Read-only digest of what a filesystem image carries, suitable for
/// `info`-style introspection without taking a write handle to the FS.
///
/// Extends with new fields as backends grow; consumers should treat
/// unknown fields as informational only.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Summary {
    /// Short identifier (`"ext4"`, `"fat32"`, `"iso9660"`, …) — same
    /// string returned by [`AnyFs::kind_string`].
    pub kind: &'static str,
    /// Whether this filesystem can mutate an already-flushed image
    /// (`add` / `rm`). False for sequential / read-only formats.
    pub supports_mutation: bool,
}

/// Probe `dev` and return a [`Summary`] describing the filesystem it
/// carries. Cheaper than [`open`] when the caller only needs the kind
/// — though today it still performs a full open under the hood. The
/// API contract is "fast enough for `fstool info`".
pub fn summary(dev: &mut dyn BlockDevice) -> Result<Summary> {
    let fs = AnyFs::open(dev)?;
    Ok(Summary {
        kind: fs.kind_string(),
        supports_mutation: fs.supports_mutation(),
    })
}

impl AnyFs {
    /// Consume `self` and return the inner filesystem as a
    /// `Box<dyn Filesystem>`. Every variant satisfies the trait
    /// (read-only backends return `Unsupported` from write methods).
    fn into_dyn_filesystem(self) -> Box<dyn crate::fs::Filesystem> {
        match self {
            #[cfg(feature = "ext")]
            Self::Ext(b) => b,
            #[cfg(feature = "fat")]
            Self::Fat32(b) => b,
            #[cfg(feature = "tar")]
            Self::Tar(b) => b,
            #[cfg(feature = "xfs")]
            Self::Xfs(b) => b,
            #[cfg(feature = "exfat")]
            Self::Exfat(b) => b,
            #[cfg(feature = "hfs-plus")]
            Self::HfsPlus(b) => b,
            #[cfg(feature = "hfs")]
            Self::Hfs(b) => b,
            #[cfg(feature = "affs")]
            Self::Affs(b) => b,
            #[cfg(feature = "littlefs")]
            Self::LittleFs(b) => b,
            #[cfg(feature = "apfs")]
            Self::Apfs(b) => b,
            #[cfg(feature = "ntfs")]
            Self::Ntfs(b) => b,
            #[cfg(feature = "f2fs")]
            Self::F2fs(b) => b,
            #[cfg(feature = "squashfs")]
            Self::Squashfs(b) => b,
            #[cfg(feature = "iso9660")]
            Self::Iso9660(b) => b,
            #[cfg(feature = "grf")]
            Self::Grf(b) => b,
            #[cfg(feature = "archive")]
            Self::Archive(fs, _, _) => fs,
            #[cfg(feature = "ramfs")]
            Self::Ramfs(b) => b,
        }
    }
}

// -- partition-aware target plumbing ------------------------------------

/// A parsed CLI image target. The user can write `disk.img` for the
/// whole image or `disk.img:N` to target the N-th partition (1-indexed,
/// matching `sgdisk -p` and `loopXpN`). Internally we store the index
/// zero-based for convenience.
#[derive(Debug, Clone)]
pub struct Target {
    pub path: PathBuf,
    /// `None` → whole disk; `Some(i)` → partition with zero-based index `i`.
    pub partition: Option<usize>,
    /// Passphrase for an encrypted container (a LUKS volume, an encrypted
    /// qcow2). Ignored when the image turns out not to be encrypted, so a
    /// caller holding one may attach it unconditionally.
    pub password: Option<String>,
}

impl Target {
    /// Parse a target spec. `disk.img:N` is the partition form; any other
    /// `:` in the path (e.g. on Windows) is preserved by only splitting on
    /// the *last* `:` and only when the trailing segment parses as a
    /// 1-based partition number.
    pub fn parse(s: &str) -> Self {
        if let Some((head, tail)) = s.rsplit_once(':')
            && let Ok(n) = tail.parse::<usize>()
            && n >= 1
        {
            return Self {
                path: PathBuf::from(head),
                partition: Some(n - 1),
                password: None,
            };
        }
        Self {
            path: PathBuf::from(s),
            partition: None,
            password: None,
        }
    }

    /// Attach a passphrase for an encrypted container.
    pub fn with_password(mut self, password: Option<String>) -> Self {
        self.password = password;
        self
    }
}

/// A disk's partition table. Box-wrapped behind [`PartitionTable`] so
/// callers can consume MBR and GPT through the same dispatch.
pub enum DetectedTable {
    Gpt(Box<Gpt>),
    Mbr(Box<Mbr>),
    Apm(Box<Apm>),
}

impl DetectedTable {
    /// Returns the inner trait object for slicing / iteration.
    pub fn as_table(&self) -> &dyn PartitionTable {
        match self {
            Self::Gpt(g) => g.as_ref(),
            Self::Mbr(m) => m.as_ref(),
            Self::Apm(a) => a.as_ref(),
        }
    }

    /// Short label for UI ("gpt" / "mbr" / "apm").
    pub fn label(&self) -> &'static str {
        match self {
            Self::Gpt(_) => "gpt",
            Self::Mbr(_) => "mbr",
            Self::Apm(_) => "apm",
        }
    }

    /// All non-empty partitions, in disk order.
    pub fn partitions(&self) -> &[Partition] {
        self.as_table().partitions()
    }
}

/// Probe `dev` for a partition table. Returns `Ok(Some(table))` when a
/// GPT or MBR is found, `Ok(None)` when sector 0 looks like an ext or
/// FAT32 image (no partition table), and `Err(_)` only on I/O failures.
///
/// GPT takes precedence: a GPT disk's sector 0 contains a *protective*
/// MBR whose only entry has type 0xEE, so we'd otherwise treat it as a
/// legacy MBR and slice incorrectly.
pub fn detect_partition_table(dev: &mut dyn BlockDevice) -> Result<Option<DetectedTable>> {
    if dev.total_size() < 512 {
        return Ok(None);
    }
    // Look at the FS signatures first — if the sector 0 carries a FAT32
    // boot record or the LBA-2 region (offset 1024) carries an ext
    // superblock, it's a bare FS, not a partition table.
    let mut s0 = [0u8; 512];
    dev.read_at(0, &mut s0)?;
    let is_fat32 = s0[510] == 0x55 && s0[511] == 0xAA && &s0[82..87] == b"FAT32";
    if is_fat32 {
        return Ok(None);
    }
    // FAT12 / FAT16 too: a DOS-formatted floppy or small volume carries
    // boot code and message strings right through the 0x1BE..0x1FE range
    // that the MBR heuristic below reads as partition entries.
    #[cfg(feature = "fat")]
    if crate::fs::fat::boot::probe(&s0).is_some() {
        return Ok(None);
    }
    let has_55aa = s0[510] == 0x55 && s0[511] == 0xAA;
    // GPT signature at LBA 1 (offset 512) is "EFI PART".
    if dev.total_size() >= 1024 {
        let mut s1_head = [0u8; 8];
        dev.read_at(512, &mut s1_head)?;
        if &s1_head == b"EFI PART" {
            let gpt = Gpt::read(dev)?;
            return Ok(Some(DetectedTable::Gpt(Box::new(gpt))));
        }
    }
    // Apple Partition Map: a Driver Descriptor Map ("ER") at block 0 plus a
    // partition map entry ("PM") at block 1. Checked before MBR — APM disks
    // carry no 0x55AA boot signature, so the two never collide.
    if Apm::probe(dev) {
        let apm = Apm::read(dev)?;
        return Ok(Some(DetectedTable::Apm(Box::new(apm))));
    }
    // Legacy MBR: 0x55AA signature plus at least one partition entry whose
    // type byte is non-zero. (A zero-FS image with a stray 0x55AA in the
    // first 512 bytes is unlikely but possible — the entry-type check
    // prevents misidentification.)
    if has_55aa {
        for i in 0..4 {
            let entry_off = 446 + i * 16;
            if s0[entry_off + 4] != 0 {
                let mbr = Mbr::read(dev)?;
                return Ok(Some(DetectedTable::Mbr(Box::new(mbr))));
            }
        }
    }
    Ok(None)
}

/// Refuse a target path whose extension marks it as a compressed image
/// (`.gz` / `.zst` / `.xz` / etc.). Mutating commands like `add` / `rm`
/// / `shell` go through [`with_target_device`], which transparently
/// decompresses to a tempfile — any mutation lands on that tempfile
/// and is silently lost when it drops. Call this from every mutating
/// CLI handler before opening the device.
///
/// Read-only commands (`ls`, `cat`, `info`, `analyze`) are fine with
/// the decompress-to-tempfile fast path and should NOT call this.
pub fn reject_compressed_for_mutation(target: &Target) -> Result<()> {
    if let Some(algo) = crate::compression::detect_path(&target.path)? {
        return Err(crate::Error::InvalidArgument(format!(
            "{}: cannot mutate a {} archive in place — decompress it first \
             (e.g. `gunzip {}`) or use `fstool repack` to rebuild a fresh image",
            target.path.display(),
            algo.name(),
            target.path.display(),
        )));
    }
    Ok(())
}

/// Run `op` with a [`BlockDevice`] that points at whatever `target`
/// resolves to: the whole disk for `disk.img`, or a partition slice for
/// `disk.img:N`. The closure opens its own [`AnyFs`] (or doesn't, e.g.
/// `info` may want to list the partition table instead).
///
/// Errors with [`crate::Error::InvalidArgument`] when `target` names a
/// partition but the image carries no partition table (or the index is
/// out of range).
pub fn with_target_device<F, R>(target: &Target, op: F) -> Result<R>
where
    F: FnOnce(&mut dyn BlockDevice) -> Result<R>,
{
    let mut disk = crate::block::open_image_maybe_compressed_with_password(
        &target.path,
        target.password.as_deref(),
    )?;
    match target.partition {
        None => op(disk.as_mut()),
        Some(idx) => {
            let table = detect_partition_table(disk.as_mut())?.ok_or_else(|| {
                crate::Error::InvalidArgument(format!(
                    "{}: no partition table found, can't target partition {}",
                    target.path.display(),
                    idx + 1
                ))
            })?;
            let mut slice = slice_partition(table.as_table(), disk.as_mut(), idx)?;
            op(&mut slice)
        }
    }
}

/// Read-only counterpart of [`with_target_device`]. Opens the
/// backing image `O_RDONLY` (via
/// [`crate::block::open_image_maybe_compressed_read_only`]) so any
/// write attempt that slips through fails with `PermissionDenied`
/// — belt-and-braces protection for callers like `fstool shell
/// --ro` that promise not to mutate the source image.
///
/// Compressed sources keep working: they're decompressed into an
/// in-memory [`crate::block::MemoryBackend`]; on session exit the
/// backend drops, taking its decompressed bytes with it.
pub fn with_target_device_read_only<F, R>(target: &Target, op: F) -> Result<R>
where
    F: FnOnce(&mut dyn BlockDevice) -> Result<R>,
{
    let mut disk = crate::block::open_image_maybe_compressed_read_only_with_password(
        &target.path,
        target.password.as_deref(),
    )?;
    match target.partition {
        None => op(disk.as_mut()),
        Some(idx) => {
            let table = detect_partition_table(disk.as_mut())?.ok_or_else(|| {
                crate::Error::InvalidArgument(format!(
                    "{}: no partition table found, can't target partition {}",
                    target.path.display(),
                    idx + 1
                ))
            })?;
            let mut slice = slice_partition(table.as_table(), disk.as_mut(), idx)?;
            op(&mut slice)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "ext")]
    use crate::block::FileBackend;
    use crate::block::MemoryBackend;
    #[cfg(feature = "ext")]
    use crate::fs::ext::{Ext, FormatOpts};

    #[cfg(feature = "ext")]
    #[test]
    fn detects_ext2_in_memory() {
        let opts = FormatOpts::default();
        let mut dev = MemoryBackend::new(opts.blocks_count as u64 * opts.block_size as u64);
        Ext::format_with(&mut dev, &opts).unwrap();
        assert_eq!(detect_fs(&mut dev).unwrap(), FsKind::Ext);
    }

    #[cfg(feature = "fat")]
    #[test]
    fn detects_fat32_in_memory() {
        let mut dev = MemoryBackend::new(64 * 1024 * 1024);
        let opts = crate::fs::fat::FatFormatOpts {
            total_sectors: 64 * 1024 * 1024 / 512,
            volume_id: 0xCAFE_F00D,
            volume_label: *b"DETECTVOL  ",
            ..Default::default()
        };
        crate::fs::fat::Fat32::format(&mut dev, &opts).unwrap();
        assert_eq!(detect_fs(&mut dev).unwrap(), FsKind::Fat32);
    }

    #[test]
    fn rejects_random_garbage() {
        let mut dev = MemoryBackend::new(64 * 1024);
        // First write a byte to make the device non-pristine.
        dev.write_at(0, b"not a filesystem").unwrap();
        assert!(detect_fs(&mut dev).is_err());
    }

    #[cfg(feature = "ext")]
    #[test]
    fn anyfs_lists_an_ext_image() {
        use tempfile::NamedTempFile;
        let opts = FormatOpts::default();
        let size = opts.blocks_count as u64 * opts.block_size as u64;
        let tmp = NamedTempFile::new().unwrap();
        let mut dev = FileBackend::create(tmp.path(), size).unwrap();
        let mut ext = Ext::format_with(&mut dev, &opts).unwrap();
        ext.flush(&mut dev).unwrap();
        dev.sync().unwrap();
        drop(dev);

        let (mut dev, mut fs) = open_image_file(tmp.path()).unwrap();
        assert_eq!(fs.kind(), FsKind::Ext);
        let entries = fs.list(dev.as_mut(), "/").unwrap();
        // Default ext format includes lost+found.
        assert!(entries.iter().any(|e| e.name == "lost+found"));
    }

    #[cfg(feature = "ext")]
    #[test]
    fn open_returns_dyn_filesystem() {
        let opts = FormatOpts::default();
        let mut dev = MemoryBackend::new(opts.blocks_count as u64 * opts.block_size as u64);
        let mut ext = Ext::format_with(&mut dev, &opts).unwrap();
        ext.flush(&mut dev).unwrap();
        drop(ext);

        let mut fs: Box<dyn crate::fs::Filesystem> = open(&mut dev).unwrap();
        assert!(fs.supports_mutation());
        let entries = fs
            .list(&mut dev, std::path::Path::new("/"))
            .expect("list /");
        assert!(entries.iter().any(|e| e.name == "lost+found"));
    }

    #[cfg(feature = "ext")]
    #[test]
    fn summary_reports_kind_and_mutability() {
        let opts = FormatOpts::default();
        let mut dev = MemoryBackend::new(opts.blocks_count as u64 * opts.block_size as u64);
        let mut ext = Ext::format_with(&mut dev, &opts).unwrap();
        ext.flush(&mut dev).unwrap();
        drop(ext);

        let s = summary(&mut dev).unwrap();
        assert_eq!(s.kind, "ext2");
        assert!(s.supports_mutation);
    }

    /// `add` on a streaming filesystem (tar) should surface
    /// `Error::Streaming`, not the generic `Unsupported` and not the
    /// `Immutable` variant that's reserved for write-once
    /// random-access formats (ISO 9660, SquashFS).
    #[cfg(feature = "tar")]
    #[test]
    fn add_on_streaming_fs_returns_streaming_error() {
        use crate::fs::tar::{TarEntryMeta, TarStreamWriter};
        // Build a minimal in-memory tar so AnyFs can open it. A
        // single `/etc/` directory entry is enough for tar's parser.
        let mut buf = Vec::<u8>::new();
        {
            let mut w = TarStreamWriter::new(&mut buf);
            w.add_dir("/etc", TarEntryMeta::default(), &[]).unwrap();
            w.finish().unwrap();
        }
        let mut dev = MemoryBackend::new(buf.len() as u64);
        dev.write_at(0, &buf).unwrap();

        let mut fs = AnyFs::open(&mut dev).unwrap();
        assert_eq!(
            fs.mutation_capability(),
            crate::fs::MutationCapability::Streaming
        );
        let err = fs
            .add_file(&mut dev, "/etc/new", std::path::Path::new("/dev/null"))
            .expect_err("add on tar must fail");
        match err {
            crate::Error::Streaming { kind, op } => {
                assert_eq!(kind, "tar");
                assert_eq!(op, "add");
            }
            other => panic!("expected Streaming, got {other:?}"),
        }
    }
}
