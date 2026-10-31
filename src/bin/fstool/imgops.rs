//! Container-level subcommands: `checksum`, `verify`, `segment`, `join`,
//! `udif-rez`, `udif-derez`, `unsign`, and the library side of `convert`
//! and `resize`. Thin wrappers over `fstool::block::imageops` and
//! `fstool::block::dmg`.

use std::path::PathBuf;

use clap::Args;

/// `fstool checksum`.
#[derive(Debug, Args)]
pub struct ChecksumArgs {
    /// The image.
    #[arg(value_name = "IMAGE")]
    pub image: PathBuf,
    /// Algorithm: crc32 or md5. Others (sha256, …) are refused.
    #[arg(
        long = "type",
        short = 't',
        value_name = "ALGO",
        default_value = "crc32"
    )]
    pub algorithm: String,
    /// What to cover: `logical` (the decoded sectors, as attached — the
    /// default; equals `hdiutil checksum -type CRC32|MD5`) or `stored`
    /// (a UDIF image's data fork as stored, or any other image's file
    /// bytes).
    #[arg(long, value_name = "SCOPE", default_value = "logical")]
    pub scope: String,
}

pub fn checksum_cmd(a: &ChecksumArgs, password: Option<&str>) -> fstool::Result<()> {
    use fstool::block::imageops::{ChecksumAlgorithm, ChecksumOptions, ChecksumScope};
    let alg = ChecksumAlgorithm::from_name(&a.algorithm)?;
    let mut o = ChecksumOptions::default();
    o.scope = match a.scope.to_ascii_lowercase().as_str() {
        "logical" | "logical-sectors" | "sectors" => ChecksumScope::LogicalSectors,
        "stored" | "stored-bytes" | "bytes" => ChecksumScope::StoredBytes,
        other => {
            return Err(fstool::Error::InvalidArgument(format!(
                "checksum: unknown --scope {other:?} (expected logical or stored)"
            )));
        }
    };
    o.password = password.map(str::to_owned);
    let c = fstool::block::imageops::image_checksum(&a.image, alg, &o)?;
    let scope = match c.scope {
        ChecksumScope::LogicalSectors => "logical sectors",
        _ => "stored bytes",
    };
    println!(
        "{} {}  {} ({scope}, {} bytes)",
        alg.name(),
        c.hex(),
        a.image.display(),
        c.bytes
    );
    Ok(())
}

/// `fstool verify`.
#[cfg(feature = "dmg")]
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// The UDIF image (the first file of a segmented one).
    #[arg(value_name = "IMAGE")]
    pub image: PathBuf,
}

#[cfg(feature = "dmg")]
pub fn verify_cmd(a: &VerifyArgs) -> fstool::Result<()> {
    use fstool::block::dmg::{ChecksumStatus, verify_udif};
    let r = verify_udif(&a.image)?;
    for c in r.checks() {
        let alg = c.stored.algorithm().map_or_else(
            || format!("type {}", c.stored.kind),
            |a| a.name().to_string(),
        );
        let line = match c.status {
            ChecksumStatus::Valid => format!("verified   {alg} {}", c.stored.hex()),
            ChecksumStatus::Mismatch => format!(
                "MISMATCH   {alg} recorded {} computed {}",
                c.stored.hex(),
                c.computed_hex()
            ),
            ChecksumStatus::Absent => "no checksum".to_string(),
            ChecksumStatus::Unsupported => format!("UNSUPPORTED checksum {alg}"),
            _ => "?".to_string(),
        };
        println!("{:>48}: {line}", c.label);
    }
    if !r.is_valid() {
        return Err(fstool::Error::InvalidImage(format!(
            "verify: {} is INVALID ({} failed check{})",
            a.image.display(),
            r.failures().count(),
            if r.failures().count() == 1 { "" } else { "s" }
        )));
    }
    println!(
        "verify: checksum of {} is VALID{}",
        a.image.display(),
        if r.checked_any() {
            ""
        } else {
            " (it records none)"
        }
    );
    Ok(())
}

#[cfg(feature = "dmg-write")]
/// Parse a size like `1m`, `512k`, `100MiB` or a plain byte count.
fn parse_size(s: &str) -> fstool::Result<u64> {
    let t = s.trim();
    let lower = t.to_ascii_lowercase();
    let (num, mult) = match lower.chars().last() {
        Some('k') => (&lower[..lower.len() - 1], 1u64 << 10),
        Some('m') => (&lower[..lower.len() - 1], 1 << 20),
        Some('g') => (&lower[..lower.len() - 1], 1 << 30),
        Some('t') => (&lower[..lower.len() - 1], 1 << 40),
        _ => return fstool::spec::parse_size(t),
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .ok_or_else(|| fstool::Error::InvalidArgument(format!("bad size {s:?}")))
}

/// `fstool segment`.
#[cfg(feature = "dmg-write")]
#[derive(Debug, Args)]
pub struct SegmentArgs {
    /// The UDIF image to split.
    #[arg(value_name = "SRC")]
    pub src: PathBuf,
    /// The first output file (`out.dmg`; the others become
    /// `out.002.dmgpart`, …).
    #[arg(value_name = "OUT")]
    pub out: PathBuf,
    /// Data-fork bytes per segment, e.g. `1m`, `650MiB`.
    #[arg(long, value_name = "SIZE", conflicts_with = "segment_count")]
    pub segment_size: Option<String>,
    /// Number of (equal) segments instead.
    #[arg(long, value_name = "N")]
    pub segment_count: Option<u32>,
    /// Size of the first segment, when it should differ.
    #[arg(long, value_name = "SIZE")]
    pub first_segment_size: Option<String>,
    /// Replace existing output files.
    #[arg(long)]
    pub force: bool,
    /// Allow a code-signed source; the segments are unsigned.
    #[arg(long)]
    pub remove_signature: bool,
}

#[cfg(feature = "dmg-write")]
fn policy(remove_signature: bool) -> fstool::block::dmg::UdifRewritePolicy {
    let mut p = fstool::block::dmg::UdifRewritePolicy::default();
    if remove_signature {
        p.signature = fstool::block::dmg::SignaturePolicy::Remove;
    }
    p
}

#[cfg(feature = "dmg-write")]
pub fn segment_cmd(a: &SegmentArgs) -> fstool::Result<()> {
    let mut o = fstool::block::dmg::SegmentOptions::default();
    if let Some(s) = &a.segment_size {
        o.segment_size = parse_size(s)?;
    }
    o.segment_count = a.segment_count;
    if let Some(s) = &a.first_segment_size {
        o.first_segment_size = Some(parse_size(s)?);
    }
    o.overwrite = a.force;
    o.policy = policy(a.remove_signature);
    let r = fstool::block::dmg::segment_udif(&a.src, &a.out, &o)?;
    for (p, n) in r.paths.iter().zip(&r.fork_lengths) {
        println!("created: {} ({n} data-fork bytes)", p.display());
    }
    println!(
        "{} segment{}, ID {}",
        r.paths.len(),
        if r.paths.len() == 1 { "" } else { "s" },
        uuid::Uuid::from_bytes(r.segment_id)
    );
    Ok(())
}

/// `fstool join`.
#[cfg(feature = "dmg-write")]
#[derive(Debug, Args)]
pub struct JoinArgs {
    /// The first file of the segment set.
    #[arg(value_name = "FIRST")]
    pub src: PathBuf,
    /// The joined single-file image.
    #[arg(value_name = "OUT")]
    pub out: PathBuf,
    /// Allow a code-signed source; the output is unsigned.
    #[arg(long)]
    pub remove_signature: bool,
}

#[cfg(feature = "dmg-write")]
pub fn join_cmd(a: &JoinArgs) -> fstool::Result<()> {
    let mut o = fstool::block::dmg::JoinOptions::default();
    o.policy = policy(a.remove_signature);
    let t = fstool::block::dmg::join_udif(&a.src, &a.out, &o)?;
    println!(
        "joined → {} ({} data-fork bytes, {} sectors)",
        a.out.display(),
        t.data_fork_length,
        t.sector_count
    );
    Ok(())
}

/// `fstool udif-derez`.
#[cfg(feature = "dmg")]
#[derive(Debug, Args)]
pub struct UdifDerezArgs {
    /// The UDIF image.
    #[arg(value_name = "IMAGE")]
    pub image: PathBuf,
    /// Only these resource types (repeatable), e.g. `--kind TEXT`.
    #[arg(long, value_name = "TYPE")]
    pub kind: Vec<String>,
    /// Leave out `blkx` (the chunk tables).
    #[arg(long)]
    pub no_blkx: bool,
    /// Write the XML here instead of stdout.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
}

#[cfg(feature = "dmg")]
pub fn udif_derez_cmd(a: &UdifDerezArgs) -> fstool::Result<()> {
    let info = fstool::block::dmg::inspect_udif(&a.image)?;
    if !info.resources_complete {
        return Err(fstool::Error::Unsupported(
            "udif-derez: the image's resource plist could not be fully parsed".into(),
        ));
    }
    let mut res = info.resources.clone();
    res.entries.retain(|r| {
        (a.kind.is_empty() || a.kind.contains(&r.kind))
            && !(a.no_blkx && r.kind == fstool::block::dmg::BLKX_RESOURCE)
    });
    let xml = res.to_xml();
    match &a.output {
        Some(p) => std::fs::write(p, xml)?,
        None => print!("{xml}"),
    }
    Ok(())
}

/// `fstool udif-rez`.
#[cfg(feature = "dmg-write")]
#[derive(Debug, Args)]
pub struct UdifRezArgs {
    /// The UDIF image to edit (in place, unless `-o`).
    #[arg(value_name = "IMAGE")]
    pub image: PathBuf,
    /// Resources to add or replace, in `udifderez -xml` form.
    #[arg(long, value_name = "FILE")]
    pub xml: Option<PathBuf>,
    /// Remove every resource but `blkx` first.
    #[arg(long)]
    pub replace_all: bool,
    /// Remove resources: `TYPE` or `TYPE:ID` (repeatable).
    #[arg(long, value_name = "TYPE[:ID]")]
    pub remove: Vec<String>,
    /// Write the result here instead of editing IMAGE.
    #[arg(long, short = 'o', value_name = "OUT")]
    pub output: Option<PathBuf>,
    /// Allow a code-signed image; the result is unsigned.
    #[arg(long)]
    pub remove_signature: bool,
}

#[cfg(feature = "dmg-write")]
pub fn udif_rez_cmd(a: &UdifRezArgs) -> fstool::Result<()> {
    let mut e = fstool::block::dmg::ResourceEdit::default();
    e.replace_all = a.replace_all;
    for spec in &a.remove {
        let (k, id) = match spec.rsplit_once(':') {
            Some((k, id)) if id.parse::<i32>().is_ok() => (k.to_string(), id.parse().ok()),
            _ => (spec.clone(), None),
        };
        e.remove.push((k, id));
    }
    if let Some(x) = &a.xml {
        let text = std::fs::read_to_string(x)?;
        e.add = fstool::block::dmg::UdifResources::from_xml(&text)?;
        // A udifderez dump includes blkx; importing it back is a no-op for
        // the chunk tables, never a replacement.
        e.add
            .entries
            .retain(|r| r.kind != fstool::block::dmg::BLKX_RESOURCE);
    }
    e.policy = policy(a.remove_signature);
    let out = a.output.as_ref().unwrap_or(&a.image);
    for r in &e.add.entries {
        println!("copying resource '{}' ({})...", r.kind, r.id);
    }
    let res = fstool::block::dmg::edit_udif_resources(&a.image, out, &e)?;
    println!(
        "{}: resources now {}",
        out.display(),
        res.kinds().join(", ")
    );
    Ok(())
}

/// `fstool unsign`.
#[cfg(feature = "dmg-write")]
#[derive(Debug, Args)]
pub struct UnsignArgs {
    /// The signed UDIF image (rewritten in place, unless `-o`).
    #[arg(value_name = "IMAGE")]
    pub image: PathBuf,
    /// Write the unsigned image here instead.
    #[arg(long, short = 'o', value_name = "OUT")]
    pub output: Option<PathBuf>,
}

#[cfg(feature = "dmg-write")]
pub fn unsign_cmd(a: &UnsignArgs) -> fstool::Result<()> {
    let out = a.output.as_ref().unwrap_or(&a.image);
    let had = fstool::block::dmg::inspect_udif(&a.image)?.code_signature();
    fstool::block::dmg::remove_code_signature(&a.image, out)?;
    match had {
        Some(s) => println!(
            "{}: removed a {}-byte code signature",
            out.display(),
            s.length
        ),
        None => println!("{}: was not signed", out.display()),
    }
    Ok(())
}

/// `fstool resize`: the container only.
pub fn resize_cmd(
    image: &std::path::Path,
    size: &str,
    discard: bool,
    remove_signature: bool,
) -> fstool::Result<()> {
    use fstool::block::imageops::{ContainerResizeOptions, ShrinkData, resize_container};
    let new_size = fstool::spec::parse_size(size)?;
    let mut o = ContainerResizeOptions::default();
    if discard {
        o.shrink = ShrinkData::Discard;
    }
    #[cfg(feature = "dmg-write")]
    {
        o.policy = policy(remove_signature);
    }
    #[cfg(not(feature = "dmg-write"))]
    let _ = remove_signature;
    let r = resize_container(image, new_size, &o)?;
    println!(
        "{}: container {} → {} bytes ({}; the filesystem and partition table inside are unchanged{})",
        image.display(),
        r.old_size,
        r.new_size,
        r.kind.name(),
        if r.discarded_data {
            "; nonzero data past the new end was DISCARDED"
        } else {
            ""
        }
    );
    Ok(())
}

/// What `fstool convert` hands the library converter.
#[cfg(feature = "dmg")]
pub struct LibConvert<'a> {
    pub src: &'a std::path::Path,
    pub dst: &'a std::path::Path,
    pub password: Option<&'a str>,
    pub format: Option<&'a str>,
    pub level: Option<u8>,
    pub checksum: Option<&'a str>,
    pub layout: Option<&'a str>,
    pub drop_resources: bool,
    pub remove_signature: bool,
    pub discard_legacy_fork: bool,
}

/// `convert` through `fstool::block::imageops::convert_image`: any UDIF
/// source or destination.
#[cfg(feature = "dmg")]
pub fn lib_convert(a: LibConvert<'_>) -> fstool::Result<()> {
    use fstool::block::imageops::{ConvertOptions, ResourcePolicy, convert_image};
    let mut o = ConvertOptions::default();
    o.password = a.password.map(str::to_owned);
    if a.drop_resources {
        o.resources = ResourcePolicy::Drop;
    }
    if a.remove_signature {
        o.policy.signature = fstool::block::dmg::SignaturePolicy::Remove;
    }
    if a.discard_legacy_fork {
        o.policy.legacy_resource_fork = fstool::block::dmg::LegacyForkPolicy::Discard;
    }
    #[cfg(feature = "dmg-write")]
    {
        use fstool::block::dmg::{UdifChecksum, UdifFormat, UdifLayout};
        if let Some(f) = a.format {
            o.udif.format = UdifFormat::from_name(f).ok_or_else(|| {
                fstool::Error::InvalidArgument(format!(
                    "convert: unknown --dmg-format {f:?} \
                     (expected UDRO, UDCO, UDZO, UDBZ, ULMO, UFBI or UDRW)"
                ))
            })?;
            o.target = Some(fstool::block::imageops::ImageKind::Udif);
        }
        o.udif.level = a.level;
        if let Some(c) = a.checksum {
            o.udif.checksum = match c.to_ascii_lowercase().as_str() {
                "crc32" | "crc" => UdifChecksum::Crc32,
                "md5" => UdifChecksum::Md5,
                "none" => UdifChecksum::None,
                _ => {
                    return Err(fstool::Error::InvalidArgument(format!(
                        "convert: unknown --dmg-checksum {c:?} (expected crc32, md5 or none)"
                    )));
                }
            };
            o.target = Some(fstool::block::imageops::ImageKind::Udif);
        }
        match a.layout.map(str::to_ascii_lowercase).as_deref() {
            None | Some("preserve") => {}
            Some("auto") => o.preserve_layout = false,
            Some("whole") | Some("none") => {
                o.preserve_layout = false;
                o.udif.layout = UdifLayout::WholeDevice;
            }
            Some(other) => {
                return Err(fstool::Error::InvalidArgument(format!(
                    "convert: unknown --dmg-layout {other:?} (expected preserve, auto or whole)"
                )));
            }
        }
        if a.layout.is_some() {
            o.target = Some(fstool::block::imageops::ImageKind::Udif);
        }
        if o.target == Some(fstool::block::imageops::ImageKind::Udif) {
            o.udif.validate()?;
        }
    }
    #[cfg(not(feature = "dmg-write"))]
    let _ = (a.format, a.level, a.checksum, a.layout);
    let r = convert_image(a.src, a.dst, &o)?;
    #[cfg(feature = "dmg-write")]
    if let Some(s) = &r.udif {
        eprintln!(
            "converted {} → {} ({}, {} → {} bytes, {} chunks)",
            a.src.display(),
            a.dst.display(),
            o.udif.format.name(),
            r.bytes,
            s.bytes_written,
            s.chunk_count
        );
        return Ok(());
    }
    eprintln!(
        "converted {} → {} ({} → {}, {} bytes)",
        a.src.display(),
        a.dst.display(),
        r.source.name(),
        r.target.name(),
        r.bytes
    );
    Ok(())
}
