//! `fstool check` and `fstool resize-fs`: read-only filesystem
//! verification, and filesystem (+ partition) resizing through typed
//! plans. Distinct from `fstool verify` (container checksums) and
//! `fstool resize` (container size), which know nothing about the
//! filesystem inside.

#[cfg(feature = "hfs-plus")]
use std::path::Path;

#[cfg(feature = "hfs-plus")]
use fstool::block::BlockDevice;

use fstool::fs::verify::{Severity, VerifyOpts, VerifyReport};
use fstool::inspect::Target;

/// `fstool check IMAGE[:N]`.
pub fn check_cmd(image: &str, max_diagnostics: usize, quiet: bool) -> fstool::Result<()> {
    let target = Target::parse(image);
    let mut opts = VerifyOpts::default();
    opts.max_diagnostics = max_diagnostics;
    let report = fstool::inspect::with_target_device_read_only(&target, |dev| {
        fstool::fs::verify::verify_volume(dev, &opts)
    })?;
    print_report(&report, quiet);
    if report.error_count > 0 {
        return Err(fstool::Error::InvalidImage(format!(
            "{image}: {} error(s) found",
            report.error_count
        )));
    }
    if !report.is_complete() {
        return Err(fstool::Error::InvalidImage(format!(
            "{image}: verification incomplete ({})",
            report
                .truncated
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(())
}

fn print_report(r: &VerifyReport, quiet: bool) {
    for d in &r.diagnostics {
        if quiet && d.severity != Severity::Error {
            continue;
        }
        println!("{d}");
    }
    if r.suppressed > 0 {
        println!("({} more finding(s) not shown)", r.suppressed);
    }
    let s = &r.stats;
    println!(
        "{}: {} file(s), {} folder(s), {} of {} block(s) free; {} node(s), {} record(s) checked",
        r.fs, s.files, s.folders, s.free_blocks, s.total_blocks, s.nodes, s.records
    );
    let verdict = if r.error_count > 0 {
        "NOT clean"
    } else if !r.is_complete() {
        "incomplete"
    } else {
        "clean"
    };
    println!(
        "{verdict}: {} error(s), {} warning(s)",
        r.error_count, r.warning_count
    );
}

#[cfg(feature = "hfs-plus")]
/// True when `path` is a plain raw image file whose length is its
/// virtual size — the only container `resize-fs` grows or cuts itself.
fn is_raw_file(path: &Path, dev_size: u64) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() || meta.len() != dev_size {
        return false;
    }
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 8];
    let _ = std::io::Read::read(&mut f, &mut head);
    !(head.starts_with(b"QFI\xfb") || head.starts_with(b"sprs") || head.starts_with(b"LUKS"))
}

#[cfg(feature = "hfs-plus")]
fn set_len(path: &Path, size: u64) -> fstool::Result<()> {
    let f = std::fs::OpenOptions::new().write(true).open(path)?;
    f.set_len(size)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(feature = "hfs-plus")]
fn human(b: u64) -> String {
    super::human_size(b)
}

#[cfg(feature = "hfs-plus")]
/// `fstool resize-fs IMAGE[:N] SIZE`.
pub fn resize_fs_cmd(
    image: &str,
    size: &str,
    dry_run: bool,
    shrink_disk: bool,
) -> fstool::Result<()> {
    use fstool::fs::hfs_plus::resize as r;
    let target = Target::parse(image);
    fstool::inspect::reject_compressed_for_mutation(&target)?;
    let new_size = fstool::spec::parse_size(size)?;
    let opts = r::ResizeOpts::default();
    let path = target.path.clone();

    let Some(index) = target.partition else {
        // A bare volume.
        let plan = {
            let mut dev = fstool::block::open_image_read_only(&path)?;
            let plan = r::plan_resize(dev.as_mut(), new_size, &opts)?;
            print_fs_plan(&plan);
            (plan, dev.total_size())
        };
        let (plan, dev_size) = plan;
        if !plan.is_feasible() {
            return Err(refused(&plan.refusals));
        }
        if dry_run {
            println!("dry run: nothing changed");
            return Ok(());
        }
        let raw = is_raw_file(&path, dev_size);
        if dev_size < new_size {
            if !raw {
                return Err(fstool::Error::InvalidArgument(format!(
                    "{}: the image is {} — grow the container to {} first \
                     (`fstool resize`), then run resize-fs",
                    path.display(),
                    human(dev_size),
                    human(new_size)
                )));
            }
            set_len(&path, new_size)?;
        }
        {
            let mut dev = fstool::block::open_image(&path)?;
            r::apply_resize(dev.as_mut(), &plan)?;
            dev.sync()?;
        }
        if new_size < dev_size {
            if raw {
                set_len(&path, new_size)?;
            } else {
                println!(
                    "note: the container is still {}; shrink it to {} to give the space back",
                    human(dev_size),
                    human(new_size)
                );
            }
        }
        println!(
            "{}: filesystem resized to {}",
            path.display(),
            human(new_size)
        );
        return Ok(());
    };

    // Inside a partition table. Work out whether the disk image itself
    // has to change: grow it when the partition is the last one and the
    // new size runs past the end; cut it after a shrink on request.
    let (disk_size, disk_new) = {
        use fstool::part::resize::{TableKind, plan_partition_resize};
        let mut disk = fstool::block::open_image_read_only(&path)?;
        let disk_size = disk.total_size();
        let here = plan_partition_resize(disk.as_mut(), index, new_size / 512, None)?;
        // GPT keeps 33 sectors (backup entries + header) after the last
        // usable LBA.
        let trailer = if here.table == TableKind::Gpt {
            33 * 512
        } else {
            0
        };
        let wanted = here.start_lba * 512 + new_size + trailer;
        let mut disk_new = None;
        if here.new_size_lba > here.max_size_lba && is_raw_file(&path, disk_size) {
            let bigger = plan_partition_resize(disk.as_mut(), index, new_size / 512, Some(wanted))?;
            if bigger.new_size_lba <= bigger.max_size_lba {
                disk_new = Some(wanted);
            }
        } else if shrink_disk && here.new_size_lba < here.old_size_lba && wanted < disk_size {
            disk_new = Some(wanted);
        }
        (disk_size, disk_new)
    };
    if shrink_disk && disk_new.is_none() {
        return Err(fstool::Error::InvalidArgument(
            "--shrink-disk: this is not a shrink, or nothing past the partition can go".into(),
        ));
    }
    let plan = {
        let mut disk = fstool::block::open_image_read_only(&path)?;
        r::plan_resize_in_partition(disk.as_mut(), index, new_size, disk_new, &opts)?
    };
    print_part_plan(&plan.partition);
    print_fs_plan(&plan.filesystem);
    if !plan.is_feasible() {
        let mut list: Vec<String> = plan
            .partition
            .refusals
            .iter()
            .map(|r| r.to_string())
            .collect();
        list.extend(plan.filesystem.refusals.iter().map(|r| r.to_string()));
        return Err(fstool::Error::InvalidArgument(format!(
            "resize refused: {}",
            list.join("; ")
        )));
    }
    if dry_run {
        println!("dry run: nothing changed");
        return Ok(());
    }
    let new_disk = plan.partition.new_disk_size;
    if new_disk < disk_size && !is_raw_file(&path, disk_size) {
        return Err(fstool::Error::InvalidArgument(
            "--shrink-disk needs a raw image file".into(),
        ));
    }
    if new_disk > disk_size {
        set_len(&path, new_disk)?;
    }
    {
        let mut disk = fstool::block::open_image(&path)?;
        r::apply_resize_in_partition(disk.as_mut(), &plan)?;
        disk.sync()?;
    }
    if new_disk < disk_size {
        set_len(&path, new_disk)?;
    }
    println!(
        "{}: partition {} and its filesystem resized to {}{}",
        path.display(),
        index + 1,
        human(new_size),
        if new_disk != disk_size {
            format!("; disk image now {}", human(new_disk))
        } else {
            String::new()
        }
    );
    Ok(())
}

#[cfg(feature = "hfs-plus")]
fn refused(list: &[fstool::fs::resize::ResizeRefusal]) -> fstool::Error {
    let v: Vec<String> = list.iter().map(|r| r.to_string()).collect();
    fstool::Error::InvalidArgument(format!("resize refused: {}", v.join("; ")))
}

#[cfg(feature = "hfs-plus")]
fn print_fs_plan(p: &fstool::fs::hfs_plus::resize::HfsPlusResizePlan) {
    println!(
        "{} {}: {} -> {} ({} -> {} blocks of {} bytes; free {} -> {})",
        if p.hfsx { "hfsx" } else { "hfs+" },
        p.direction,
        human(p.old_size),
        human(p.new_size),
        p.old_total_blocks,
        p.new_total_blocks,
        p.block_size,
        p.old_free_blocks,
        p.new_free_blocks
    );
    println!(
        "  reachable without moving data: {} .. {} ({} with the current bitmap)",
        human(p.min_size),
        human(p.max_size),
        human(p.max_size_in_place)
    );
    if let Some(e) = p.bitmap_extension {
        println!(
            "  allocation bitmap grows by {} block(s) at block {}",
            e.block_count, e.start_block
        );
    }
    if p.journaled {
        println!("  journaled (journal empty)");
    }
    for r in &p.refusals {
        println!("  refused: {r}");
    }
}

#[cfg(feature = "hfs-plus")]
fn print_part_plan(p: &fstool::part::resize::PartitionResizePlan) {
    println!(
        "{:?} partition {}: {} -> {} sectors at LBA {} (room for at most {}){}",
        p.table,
        p.index + 1,
        p.old_size_lba,
        p.new_size_lba,
        p.start_lba,
        p.max_size_lba,
        if p.new_disk_size != p.old_disk_size {
            format!(
                "; disk {} -> {}",
                human(p.old_disk_size),
                human(p.new_disk_size)
            )
        } else {
            String::new()
        }
    );
    for r in &p.refusals {
        println!("  refused: {r}");
    }
}
