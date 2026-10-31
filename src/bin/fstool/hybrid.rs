//! `fstool makehybrid`: an ISO 9660 / Joliet / HFS+ hybrid image from a
//! host directory or any filesystem image, with flags after
//! `hdiutil makehybrid`'s.

use std::path::{Path, PathBuf};

use clap::Args;

use fstool::block::{BlockDevice, FileBackend};
use fstool::fs::hybrid::{
    BootEmulation, BootOptions, BootPlatform, FilesystemPayloads, HybridOptions, HybridPlan,
    IsoLevel, SourceTree,
};

/// `fstool makehybrid`.
#[derive(Debug, Args)]
pub struct MakehybridArgs {
    /// The source: a host directory, or an image (`IMAGE[:N]`) whose
    /// filesystem is copied.
    #[arg(value_name = "SRC")]
    pub src: String,
    /// The image to write. Written beside it under a temporary name and
    /// renamed into place once complete.
    #[arg(short = 'o', long, value_name = "OUT")]
    pub output: PathBuf,
    /// Advertise an ISO 9660 primary hierarchy. Without any of `--iso`,
    /// `--joliet`, `--hfs`, all three are made.
    #[arg(long)]
    pub iso: bool,
    /// Advertise a Joliet hierarchy.
    #[arg(long)]
    pub joliet: bool,
    /// Advertise an HFS+ volume (in an `Apple_HFS` partition).
    #[arg(long)]
    pub hfs: bool,
    /// Add Rock Ridge to the ISO 9660 hierarchy (the default).
    #[arg(long, overrides_with = "no_rock_ridge")]
    pub rock_ridge: bool,
    /// Leave Rock Ridge out.
    #[arg(long)]
    pub no_rock_ridge: bool,
    /// ISO 9660 interchange level: 1 (8.3 names), 2 (30-character names,
    /// the default) or 3 (level 2 plus files of 4 GiB and more).
    #[arg(long, value_name = "N", default_value_t = 2)]
    pub iso_level: u8,
    /// Allow 103-character Joliet names (the specification says 64).
    #[arg(long)]
    pub joliet_long: bool,
    /// Label of every view (default: the source directory's name).
    #[arg(long, visible_alias = "volume-name", short = 'V', value_name = "NAME")]
    pub default_volume_name: Option<String>,
    /// ISO 9660 volume identifier (32 d-characters).
    #[arg(long, value_name = "NAME")]
    pub iso_volume_name: Option<String>,
    /// Joliet volume identifier (16 characters).
    #[arg(long, value_name = "NAME")]
    pub joliet_volume_name: Option<String>,
    /// HFS+ volume name.
    #[arg(long, value_name = "NAME")]
    pub hfs_volume_name: Option<String>,
    /// Hide entries matching GLOB from the ISO 9660 hierarchy (repeatable).
    /// A GLOB without `/` matches names, one with `/` paths.
    #[arg(long, value_name = "GLOB")]
    pub hide_iso: Vec<String>,
    /// Hide entries matching GLOB from Joliet.
    #[arg(long, value_name = "GLOB")]
    pub hide_joliet: Vec<String>,
    /// Hide entries matching GLOB from HFS+.
    #[arg(long, value_name = "GLOB")]
    pub hide_hfs: Vec<String>,
    /// Show entries matching GLOB in ISO 9660 only.
    #[arg(long, value_name = "GLOB")]
    pub only_iso: Vec<String>,
    /// Show entries matching GLOB in Joliet only.
    #[arg(long, value_name = "GLOB")]
    pub only_joliet: Vec<String>,
    /// Show entries matching GLOB in HFS+ only.
    #[arg(long, value_name = "GLOB")]
    pub only_hfs: Vec<String>,
    /// Folder to bless on the HFS+ volume (a path in SRC).
    #[arg(long, value_name = "PATH")]
    pub hfs_blessed_directory: Option<String>,
    /// Folder the Finder opens when the HFS+ volume mounts.
    #[arg(long, value_name = "PATH")]
    pub hfs_openfolder: Option<String>,
    /// 64-bit HFS+ volume identifier, hex (macOS derives the UUID from it).
    #[arg(long, value_name = "HEX")]
    pub hfs_volume_id: Option<String>,
    /// HFS+ allocation block size (a power of two ≥ 2048).
    #[arg(long, value_name = "BYTES", default_value_t = 2048)]
    pub hfs_block_size: u32,
    /// Case-sensitive HFSX instead of HFS+.
    #[arg(long)]
    pub hfsx: bool,
    /// Do not carry xattrs (resource forks, Finder info) to HFS+.
    #[arg(long)]
    pub no_hfs_xattrs: bool,
    /// ISO 9660 system identifier.
    #[arg(long, value_name = "ID")]
    pub system_id: Option<String>,
    /// ISO 9660 volume set identifier.
    #[arg(long, value_name = "ID")]
    pub volume_set: Option<String>,
    /// ISO 9660 publisher identifier.
    #[arg(long, value_name = "ID")]
    pub publisher: Option<String>,
    /// ISO 9660 data preparer identifier.
    #[arg(long, value_name = "ID")]
    pub preparer: Option<String>,
    /// ISO 9660 application identifier (default: fstool).
    #[arg(long, value_name = "ID")]
    pub application: Option<String>,
    /// ISO 9660 abstract file identifier.
    #[arg(long, value_name = "FILE")]
    pub abstract_file: Option<String>,
    /// ISO 9660 bibliographic file identifier.
    #[arg(long, value_name = "FILE")]
    pub bibliography_file: Option<String>,
    /// ISO 9660 copyright file identifier.
    #[arg(long, value_name = "FILE")]
    pub copyright_file: Option<String>,
    /// El Torito boot image (a path in SRC).
    #[arg(long, value_name = "PATH")]
    pub eltorito_boot: Option<String>,
    /// Platform of `--eltorito-boot`: x86 (default), efi, ppc, mac.
    #[arg(long, value_name = "PLATFORM", default_value = "x86")]
    pub eltorito_platform: String,
    /// Emulation of `--eltorito-boot`: none (default), floppy (size from
    /// the image), hard-disk.
    #[arg(long, value_name = "MODE", default_value = "none")]
    pub eltorito_emulation: String,
    /// Shorthand for `--eltorito-emulation none`.
    #[arg(long)]
    pub no_emul_boot: bool,
    /// Shorthand for `--eltorito-emulation hard-disk`.
    #[arg(long)]
    pub hard_disk_boot: bool,
    /// 512-byte sectors the firmware loads (no emulation; default 4).
    #[arg(long, value_name = "N")]
    pub boot_load_size: Option<u16>,
    /// Real-mode load segment, hex or decimal (default 0x7C0).
    #[arg(long, value_name = "SEG")]
    pub boot_load_seg: Option<String>,
    /// A second, EFI El Torito entry (a path in SRC, e.g. an ESP image).
    #[arg(long, value_name = "PATH")]
    pub eltorito_efi_boot: Option<String>,
    /// Volume date, seconds since the Unix epoch (default:
    /// `SOURCE_DATE_EPOCH`, else now).
    #[arg(long, value_name = "EPOCH")]
    pub create_date: Option<i64>,
    /// Print the plan and the report; write nothing.
    #[arg(long, short = 'n')]
    pub dry_run: bool,
    /// Replace OUT if it exists.
    #[arg(long, visible_alias = "ov")]
    pub force: bool,
    /// Skip re-reading every view after writing.
    #[arg(long)]
    pub no_verify: bool,
    /// Print only errors.
    #[arg(long, short = 'q')]
    pub quiet: bool,
}

fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

fn options(a: &MakehybridArgs, default_name: &str) -> fstool::Result<HybridOptions> {
    let bad = |m: String| fstool::Error::InvalidArgument(format!("makehybrid: {m}"));
    let mut o = HybridOptions::new(
        a.default_volume_name
            .clone()
            .unwrap_or_else(|| default_name.to_string()),
    );
    let all = !(a.iso || a.joliet || a.hfs);
    o.iso.enabled = all || a.iso;
    o.joliet.enabled = all || a.joliet;
    o.hfs.enabled = all || a.hfs;
    o.iso.rock_ridge = !a.no_rock_ridge;
    o.iso.level = match a.iso_level {
        1 => IsoLevel::L1,
        2 => IsoLevel::L2,
        3 => IsoLevel::L3,
        n => return Err(bad(format!("--iso-level {n}: use 1, 2 or 3"))),
    };
    o.joliet.long_names = a.joliet_long;
    o.iso.volume_id = a.iso_volume_name.clone();
    o.joliet.volume_id = a.joliet_volume_name.clone();
    o.hfs.volume_name = a.hfs_volume_name.clone();
    o.iso.hide = a.hide_iso.clone();
    o.joliet.hide = a.hide_joliet.clone();
    o.hfs.hide = a.hide_hfs.clone();
    o.iso.only = a.only_iso.clone();
    o.joliet.only = a.only_joliet.clone();
    o.hfs.only = a.only_hfs.clone();
    o.hfs.blessed_folder = a.hfs_blessed_directory.clone();
    o.hfs.open_folder = a.hfs_openfolder.clone();
    if let Some(id) = &a.hfs_volume_id {
        let v = u64::from_str_radix(id.trim_start_matches("0x"), 16)
            .map_err(|_| bad(format!("--hfs-volume-id {id:?} is not hex")))?;
        o.hfs.volume_identifier = Some(v);
    }
    o.hfs.block_size = a.hfs_block_size;
    o.hfs.case_sensitive = a.hfsx;
    o.hfs.xattrs = !a.no_hfs_xattrs;
    let set = |dst: &mut String, v: &Option<String>| {
        if let Some(v) = v {
            *dst = v.clone();
        }
    };
    set(&mut o.iso.system_id, &a.system_id);
    set(&mut o.iso.volume_set_id, &a.volume_set);
    set(&mut o.iso.publisher_id, &a.publisher);
    set(&mut o.iso.preparer_id, &a.preparer);
    o.iso.application_id = a
        .application
        .clone()
        .unwrap_or_else(|| format!("FSTOOL {}", env!("CARGO_PKG_VERSION")));
    set(&mut o.iso.abstract_file, &a.abstract_file);
    set(&mut o.iso.bibliographic_file, &a.bibliography_file);
    set(&mut o.iso.copyright_file, &a.copyright_file);
    if let Some(img) = &a.eltorito_boot {
        let mut b = BootOptions::new(img.clone());
        b.platform = platform(&a.eltorito_platform).ok_or_else(|| {
            bad(format!(
                "--eltorito-platform {:?}: use x86, efi, ppc or mac",
                a.eltorito_platform
            ))
        })?;
        let mode = if a.hard_disk_boot {
            "hard-disk"
        } else if a.no_emul_boot {
            "none"
        } else {
            a.eltorito_emulation.as_str()
        };
        b.emulation = match mode {
            "none" => BootEmulation::NoEmulation,
            "hard-disk" | "hd" => BootEmulation::HardDisk,
            // The size picks the floppy; the planner checks it.
            "floppy" => BootEmulation::Floppy144,
            m => return Err(bad(format!("--eltorito-emulation {m:?}"))),
        };
        b.load_sectors = a.boot_load_size;
        if let Some(s) = &a.boot_load_seg {
            let v = parse_num(s)
                .filter(|v| *v <= u64::from(u16::MAX))
                .ok_or_else(|| bad(format!("--boot-load-seg {s:?}")))?;
            b.load_segment = v as u16;
        }
        o.iso.boot.push(b);
    }
    if let Some(img) = &a.eltorito_efi_boot {
        let mut b = BootOptions::new(img.clone());
        b.platform = BootPlatform::Efi;
        o.iso.boot.push(b);
    }
    o.create_date = a.create_date.unwrap_or_else(|| {
        std::env::var("SOURCE_DATE_EPOCH")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
            })
    });
    Ok(o)
}

fn platform(s: &str) -> Option<BootPlatform> {
    Some(match s.to_ascii_lowercase().as_str() {
        "x86" | "bios" | "i386" => BootPlatform::X86,
        "efi" | "uefi" => BootPlatform::Efi,
        "ppc" | "powerpc" => BootPlatform::PowerPc,
        "mac" => BootPlatform::Mac,
        _ => return None,
    })
}

/// Pick the floppy emulation matching the boot image's size.
fn fix_floppy(o: &mut HybridOptions, tree: &SourceTree) {
    for b in &mut o.iso.boot {
        if b.emulation != BootEmulation::Floppy144 {
            continue;
        }
        let len = tree
            .lookup(&b.image)
            .and_then(|n| match tree.node(n).kind {
                fstool::fs::hybrid::SourceKind::File { content } => Some(tree.content(content).len),
                _ => None,
            })
            .unwrap_or(0);
        b.emulation = match len {
            1_228_800 => BootEmulation::Floppy12,
            2_949_120 => BootEmulation::Floppy288,
            _ => BootEmulation::Floppy144,
        };
    }
}

fn print_plan(plan: &HybridPlan, quiet: bool, out: &Path) {
    if quiet {
        return;
    }
    let views: Vec<String> = plan.view_ids().iter().map(|v| v.to_string()).collect();
    println!(
        "{}: {} ({} sectors, {} bytes), views: {}",
        out.display(),
        human(plan.total_bytes()),
        plan.total_sectors(),
        plan.total_bytes(),
        views.join(", ")
    );
    for (v, k, val) in plan.summary() {
        println!("  {v} {k}: {val}");
    }
    println!("  layout:");
    for r in plan.regions() {
        let owner = r
            .view
            .map(|v| v.to_string())
            .unwrap_or_else(|| "shared".into());
        println!(
            "    {:>10} +{:<10} {owner}: {}",
            r.extent.lba, r.extent.sectors, r.label
        );
    }
    println!("  {} payload(s) placed once", plan.files().len());
    let items = plan.report().items();
    if !items.is_empty() {
        println!("  report ({} item(s)):", items.len());
        for i in items {
            println!("    {i}");
        }
    }
}

fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < U.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.2} {}", U[u])
    }
}

/// Write `plan` to a temporary sibling of `out`, verify it, rename it
/// into place.
fn emit(
    plan: &HybridPlan,
    a: &MakehybridArgs,
    write: &mut dyn FnMut(&HybridPlan, &mut dyn BlockDevice) -> fstool::Result<()>,
) -> fstool::Result<()> {
    if a.output.exists() && !a.force {
        return Err(fstool::Error::InvalidArgument(format!(
            "makehybrid: {} exists (pass --force to replace it)",
            a.output.display()
        )));
    }
    let name = a
        .output
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "image".into());
    let tmp = a.output.with_file_name(format!(".{name}.fstool-tmp"));
    let result = (|| -> fstool::Result<()> {
        let mut dev = FileBackend::create(&tmp, plan.total_bytes())?;
        write(plan, &mut dev)?;
        if !a.no_verify {
            plan.verify(&mut dev)?;
        }
        dev.sync()?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            std::fs::rename(&tmp, &a.output)?;
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// `fstool makehybrid`.
pub fn makehybrid_cmd(a: &MakehybridArgs) -> fstool::Result<()> {
    let src = Path::new(&a.src);
    if src.is_dir() {
        let default_name = src
            .canonicalize()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "CDROM".into());
        let mut o = options(a, &default_name)?;
        let tree = SourceTree::from_host_dir(src)?;
        fix_floppy(&mut o, &tree);
        let plan = HybridPlan::new(tree, &o)?;
        print_plan(&plan, a.quiet, &a.output);
        if a.dry_run {
            return Ok(());
        }
        emit(&plan, a, &mut |plan, dev| Ok(plan.write(dev)?))?;
    } else {
        let target = fstool::inspect::Target::parse(&a.src);
        let default_name = target
            .path
            .file_stem()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "CDROM".into());
        let mut o = options(a, &default_name)?;
        fstool::inspect::with_target_device_read_only(&target, |sdev| {
            let mut fs = fstool::inspect::open(sdev)?;
            let tree = SourceTree::from_filesystem(fs.as_mut(), sdev)?;
            fix_floppy(&mut o, &tree);
            let plan = HybridPlan::new(tree, &o)?;
            print_plan(&plan, a.quiet, &a.output);
            if a.dry_run {
                return Ok(());
            }
            emit(&plan, a, &mut |plan, dev| {
                let mut opener = FilesystemPayloads::new(fs.as_mut(), &mut *sdev);
                Ok(plan.write_with(dev, &mut opener)?)
            })
        })?;
    }
    if !a.quiet {
        println!("wrote {}", a.output.display());
    }
    Ok(())
}
