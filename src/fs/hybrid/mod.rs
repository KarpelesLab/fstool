//! Hybrid optical images: one sector space, one copy of every file, and
//! several filesystem views over it — ISO 9660 (with Rock Ridge), Joliet
//! and HFS+ today, UDF through the same [`HybridView`] interface.
//!
//! Concatenating individually valid images does not produce a hybrid:
//! their sector addresses have not received the news that they moved.
//! A hybrid is planned as a whole instead:
//!
//! ```text
//! LBA 0..15    system area: Apple Partition Map (DDM + 2 entries) when HFS+
//! LBA 16..     volume recognition: PVD, El Torito boot record, Joliet SVD,
//!              terminator (then a UDF VRS, when a UDF view is added)
//! ...          head metadata: El Torito catalog, path tables, ISO 9660 and
//!              Joliet directories, Rock Ridge continuation areas
//! P            ┌ Apple_HFS partition: volume header (byte P*2048+1024),
//!              │ bitmap, extents / catalog / attributes B-trees, a pool for
//!              │ HFS+-only blocks (symlink targets, resource forks, xattrs)
//!              │ payloads listed by HFS+ — shared: the ISO 9660 / Joliet
//!              │ records point at these very sectors
//!              └ alternate volume header (last 1 KiB of the partition)
//! ...          payloads hidden from HFS+ (outside its partition, so HFS+
//!              never sees blocks it does not own)
//! ...          tail metadata of other views; end-relative claims
//! ```
//!
//! This is the arrangement `hdiutil makehybrid` produces (an APM whose
//! `Apple_HFS` partition starts right after the ISO 9660 metadata and
//! holds the file data), so macOS mounts the HFS+ view and every other
//! system the ISO 9660 one; the ISO volume space covers the whole image.
//! HFS+ allocation blocks are 2048 bytes by default, one per sector, so
//! file extents line up with ISO 9660 sectors exactly.
//!
//! # Use
//!
//! ```no_run
//! # fn main() -> Result<(), fstool::fs::hybrid::HybridError> {
//! use fstool::block::FileBackend;
//! use fstool::fs::hybrid::{HybridOptions, HybridPlan, SourceTree};
//!
//! let tree = SourceTree::from_host_dir("dist".as_ref())?;
//! let mut opts = HybridOptions::new("MyApp 1.0");
//! opts.hfs.hide.push("*.exe".into());
//! opts.joliet.hide.push("*.app".into());
//! let plan = HybridPlan::new(tree, &opts)?;
//! for item in plan.report().items() {
//!     eprintln!("{item}");
//! }
//! let mut dev = FileBackend::create("myapp.iso", plan.total_bytes())?;
//! plan.write(&mut dev)?;
//! plan.verify(&mut dev)?;
//! # Ok(()) }
//! ```
//!
//! [`HybridPlan::new`] does all the planning and validation up front — it
//! is inspectable ([`HybridPlan::regions`], [`HybridPlan::files`],
//! [`HybridPlan::report`]) before a byte is written. [`HybridPlan::write`]
//! streams each payload once through a bounded buffer, then lets each
//! view write its metadata. [`HybridPlan::verify`] re-reads every view
//! with fstool's own independent readers and compares it to the plan.
//!
//! Anything a view cannot represent exactly — names mapped to
//! d-characters, names truncated for Joliet, symlinks absent from Joliet,
//! files of 4 GiB and more below ISO level 3, xattrs outside HFS+ — is
//! listed in the [`HybridReport`], never dropped silently.
//!
//! # Adding a view
//!
//! See [`HybridView`]: a view states its needs (volume recognition
//! sectors, fixed LBAs, floating head / tail runs, end-relative runs, a
//! payload-enclosing partition, system-area bytes), the planner assigns
//! them, and the view writes inside its share. [`HybridPlan::with_views`]
//! takes extra views; [`build_views`] is where an option-driven built-in
//! view (UDF) is wired in.

mod apm;
mod error;
mod glob;
mod hfs;
mod iso;
mod names;
mod plan;
mod report;
mod source;
mod view;

pub use error::{HybridError, Result};
pub use hfs::HfsView;
pub use iso::IsoView;
pub use plan::{HybridPlan, PlannedFile, PlannedRegion};
pub use report::{HybridReport, OmitReason, ReportItem, ReportKind};
pub use source::{
    Content, ContentId, EntryMeta, FilesystemPayloads, HostPayloads, NodeId, Payload,
    PayloadOpener, SourceKind, SourceNode, SourceTree,
};
pub use view::{
    ByteRequest, EndRequest, Extent, FixedRequest, HybridView, PayloadEntry, PayloadLayout,
    PayloadZone, Placement, SectorRequest, ViewId, ViewInput, ViewNeeds, ViewPlacement, Visibility,
    WrapPlacement, WrapRequest,
};

use crate::fs::hfs_plus::FinderInfo;

/// ECMA-119 interchange level of the primary hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum IsoLevel {
    /// 8.3 names, 8-character directory names.
    L1,
    /// 30-character names (31 for directories).
    #[default]
    L2,
    /// Level 2 names plus multi-extent files of 4 GiB and more.
    L3,
}

/// El Torito emulation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum BootEmulation {
    /// No emulation: the firmware loads `load_sectors` 512-byte sectors.
    #[default]
    NoEmulation,
    /// 1.2 MB floppy image.
    Floppy12,
    /// 1.44 MB floppy image.
    Floppy144,
    /// 2.88 MB floppy image.
    Floppy288,
    /// Hard-disk image (MBR first sector).
    HardDisk,
}

/// El Torito platform id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum BootPlatform {
    /// x86 BIOS.
    #[default]
    X86,
    /// UEFI.
    Efi,
    /// PowerPC.
    PowerPc,
    /// Mac.
    Mac,
}

/// One El Torito boot entry; the first is the default entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BootOptions {
    /// Path of the boot image in the source tree. It is placed even if
    /// hidden from every view.
    pub image: String,
    /// Firmware platform.
    pub platform: BootPlatform,
    /// Emulation mode.
    pub emulation: BootEmulation,
    /// Real-mode load segment (0: the default 0x7C0).
    pub load_segment: u16,
    /// 512-byte sectors to load (no emulation). `None`: 4 for x86 (the
    /// conventional isolinux / GRUB value), the whole image for EFI.
    pub load_sectors: Option<u16>,
    /// Id string of the catalog entry.
    pub id_string: String,
}

impl BootOptions {
    /// A no-emulation x86 entry for `image`.
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            platform: BootPlatform::X86,
            emulation: BootEmulation::NoEmulation,
            load_segment: 0,
            load_sectors: None,
            id_string: String::new(),
        }
    }
}

/// The ISO 9660 primary view (and Rock Ridge on it).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IsoOptions {
    /// Advertise the primary hierarchy.
    pub enabled: bool,
    /// Interchange level.
    pub level: IsoLevel,
    /// Add Rock Ridge (POSIX names, modes, owners, times, symlinks,
    /// device nodes, hard-link counts).
    pub rock_ridge: bool,
    /// Volume identifier (`None`: [`HybridOptions::volume_name`]), mapped
    /// to 32 d-characters.
    pub volume_id: Option<String>,
    /// System identifier.
    pub system_id: String,
    /// Volume set identifier.
    pub volume_set_id: String,
    /// Publisher identifier.
    pub publisher_id: String,
    /// Data preparer identifier.
    pub preparer_id: String,
    /// Application identifier.
    pub application_id: String,
    /// Copyright file identifier (a file in the root).
    pub copyright_file: String,
    /// Abstract file identifier.
    pub abstract_file: String,
    /// Bibliographic file identifier.
    pub bibliographic_file: String,
    /// Globs hidden from the primary hierarchy.
    pub hide: Vec<String>,
    /// Globs shown in the primary hierarchy only (hidden from the others).
    pub only: Vec<String>,
    /// El Torito boot entries.
    pub boot: Vec<BootOptions>,
}

impl Default for IsoOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            level: IsoLevel::default(),
            rock_ridge: true,
            volume_id: None,
            system_id: String::new(),
            volume_set_id: String::new(),
            publisher_id: String::new(),
            preparer_id: String::new(),
            application_id: String::new(),
            copyright_file: String::new(),
            abstract_file: String::new(),
            bibliographic_file: String::new(),
            hide: Vec::new(),
            only: Vec::new(),
            boot: Vec::new(),
        }
    }
}

/// The Joliet view.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JolietOptions {
    /// Advertise the Joliet hierarchy.
    pub enabled: bool,
    /// Joliet volume identifier (`None`: the volume name), 16 characters.
    pub volume_id: Option<String>,
    /// Allow 103-character names instead of the specification's 64.
    pub long_names: bool,
    /// Globs hidden from Joliet.
    pub hide: Vec<String>,
    /// Globs shown in Joliet only.
    pub only: Vec<String>,
}

impl Default for JolietOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            volume_id: None,
            long_names: false,
            hide: Vec::new(),
            only: Vec::new(),
        }
    }
}

/// The HFS+ view.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HfsOptions {
    /// Advertise the HFS+ volume (in an `Apple_HFS` APM partition).
    pub enabled: bool,
    /// Volume name (`None`: the volume name).
    pub volume_name: Option<String>,
    /// Allocation block size: a power of two, at least 2048.
    pub block_size: u32,
    /// Case-sensitive HFSX instead of HFS+.
    pub case_sensitive: bool,
    /// Folder to bless (`finderInfo[0]`; the system folder for booting).
    pub blessed_folder: Option<String>,
    /// Folder the Finder opens on mount (`finderInfo[2]`).
    pub open_folder: Option<String>,
    /// 64-bit volume identifier (`finderInfo[6..8]`), from which macOS
    /// derives the volume UUID.
    pub volume_identifier: Option<u64>,
    /// Finder info to set, by tree path (`"/"` is the root folder).
    pub finder_info: Vec<(String, FinderInfo)>,
    /// Carry each entry's xattrs (resource forks, Finder info, others).
    pub xattrs: bool,
    /// Globs hidden from HFS+.
    pub hide: Vec<String>,
    /// Globs shown in HFS+ only.
    pub only: Vec<String>,
}

impl Default for HfsOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            volume_name: None,
            block_size: 2048,
            case_sensitive: false,
            blessed_folder: None,
            open_folder: None,
            volume_identifier: None,
            finder_info: Vec::new(),
            xattrs: true,
            hide: Vec::new(),
            only: Vec::new(),
        }
    }
}

/// Everything about a hybrid image except its contents.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HybridOptions {
    /// Default label of every view.
    pub volume_name: String,
    /// Volume dates, seconds since the Unix epoch (0: 1970, reproducible).
    pub create_date: i64,
    /// The ISO 9660 primary view.
    pub iso: IsoOptions,
    /// The Joliet view.
    pub joliet: JolietOptions,
    /// The HFS+ view.
    pub hfs: HfsOptions,
    /// `hide` / `only` globs for views beyond the built-in three (a
    /// view added through [`HybridPlan::with_views`]).
    pub view_filters: Vec<ViewFilter>,
}

/// `hide` / `only` globs of one view.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ViewFilter {
    /// The view.
    pub view: ViewId,
    /// Globs hidden from it.
    pub hide: Vec<String>,
    /// Globs shown in it only.
    pub only: Vec<String>,
}

impl ViewFilter {
    /// Filters for `view`.
    pub fn new(view: ViewId, hide: Vec<String>, only: Vec<String>) -> Self {
        Self { view, hide, only }
    }
}

impl HybridOptions {
    /// ISO 9660 level 2 with Rock Ridge, Joliet and HFS+, all labelled
    /// `volume_name`.
    pub fn new(volume_name: impl Into<String>) -> Self {
        Self {
            volume_name: volume_name.into(),
            create_date: 0,
            iso: IsoOptions::default(),
            joliet: JolietOptions::default(),
            hfs: HfsOptions::default(),
            view_filters: Vec::new(),
        }
    }
}

impl Default for HybridOptions {
    fn default() -> Self {
        Self::new("CDROM")
    }
}

/// The built-in views `opts` enables, in the order the planner calls
/// them (ISO 9660 first: its descriptor set opens the volume recognition
/// area). This is the place an option-driven UDF view is added.
pub fn build_views(opts: &HybridOptions) -> Vec<Box<dyn HybridView>> {
    let mut v: Vec<Box<dyn HybridView>> = Vec::new();
    if opts.iso.enabled || opts.joliet.enabled {
        v.push(Box::new(IsoView::new(opts)));
    }
    if opts.hfs.enabled {
        v.push(Box::new(HfsView::new(opts)));
    }
    v
}

/// The per-view `hide` / `only` globs of `opts`.
pub(crate) fn filters(opts: &HybridOptions) -> Vec<(ViewId, Vec<String>, Vec<String>)> {
    let mut v = vec![
        (
            ViewId::Iso9660,
            opts.iso.hide.clone(),
            opts.iso.only.clone(),
        ),
        (
            ViewId::Joliet,
            opts.joliet.hide.clone(),
            opts.joliet.only.clone(),
        ),
        (
            ViewId::HfsPlus,
            opts.hfs.hide.clone(),
            opts.hfs.only.clone(),
        ),
    ];
    for f in &opts.view_filters {
        v.push((f.view, f.hide.clone(), f.only.clone()));
    }
    v
}

#[cfg(test)]
mod tests;
