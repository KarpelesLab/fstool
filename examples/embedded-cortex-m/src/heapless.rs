//! The same idea as `main.rs`, one step further down: **no allocator at
//! all**.
//!
//! There is no `extern crate alloc` and no `#[global_allocator]` here, and
//! fstool is pulled in with `fat` but not `alloc`. If any reachable line of
//! the driver could allocate, this would not link — rustc refuses a binary
//! that needs the `alloc` crate without an allocator to back it. That
//! failure mode is the point of this program: it is a compile-time proof,
//! not a runtime demo.
//!
//! It formats a small FAT12 volume in a static RAM buffer with the driver's
//! own formatter, then mounts it, writes a file, lists the root and reads
//! the file back.
//!
//! Then it does it again the way a card reader has to, not knowing what the
//! card holds: `fstool::fs::mount` probes it — exFAT or FAT, whole card or
//! partition — and hands back whichever volume it found, and a function
//! written once against the `fs::volume` traits appends to a log on it.
//! That links the exFAT driver too, so this binary is the same compile-time
//! proof for `exfat` as for `fat`. Both speak the one `SectorDriver`
//! implemented below.

#![no_std]
#![no_main]

use core::ptr;

use fstool::device::SectorDriver;
use fstool::fs::fat::{FatKind, FormatOpts, Volume};
use fstool::fs::volume::{Volume as _, VolumeDirIter, VolumeFile};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Output sink the optimiser cannot see through, so the work stays.
#[inline(never)]
fn sink(v: u32) {
    unsafe { ptr::write_volatile(0x2000_0000 as *mut u32, v) }
}

/// Sectors in the RAM card: 512 KiB.
const SECTORS: usize = 1024;
const SECTOR: usize = 512;

/// The "card": one static buffer, no heap.
static mut CARD: [u8; SECTORS * SECTOR] = [0; SECTORS * SECTOR];

/// A [`SectorDriver`] over that buffer. A real program implements these
/// four methods against its SD/SPI peripheral instead.
struct RamCard;

impl SectorDriver for RamCard {
    type Error = core::convert::Infallible;

    fn sector_size(&self) -> u32 {
        SECTOR as u32
    }

    fn sector_count(&self) -> u64 {
        SECTORS as u64
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        let at = lba as usize * SECTOR;
        // SAFETY: single-threaded bare-metal program; the card is touched
        // only through this driver.
        let card = unsafe { &*ptr::addr_of!(CARD) };
        buf.copy_from_slice(&card[at..at + buf.len()]);
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
        let at = lba as usize * SECTOR;
        // SAFETY: as above.
        let card = unsafe { &mut *ptr::addr_of_mut!(CARD) };
        card[at..at + buf.len()].copy_from_slice(buf);
        Ok(())
    }
}

// Pinned into its own section so the linker script can KEEP it: under
// `--gc-sections` an entry point nothing references is otherwise fair game.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.reset")]
pub extern "C" fn reset() -> ! {
    // A blank card gets a filesystem — no heap needed for that either.
    let opts = FormatOpts {
        label: *b"HEAPLESS   ",
        ..FormatOpts::default()
    };
    if Volume::<_, 512>::format(RamCard, &opts).and_then(Volume::unmount).is_err() {
        loop {}
    }

    let mut vol = match Volume::<_, 512>::mount(RamCard) {
        Ok(v) => v,
        Err(_) => loop {},
    };
    sink(matches!(vol.kind(), FatKind::Fat12) as u32);
    sink(vol.free_clusters().unwrap_or(0));

    // Create a file with a long name, write to it, and read it back.
    let body: &[u8] = b"hello from a microcontroller, with no heap";
    let mut f = match vol.create_file("/a long name.txt") {
        Ok(f) => f,
        Err(_) => loop {},
    };
    if f.write_all(&mut vol, body).is_err() || f.flush(&mut vol).is_err() {
        loop {}
    }

    let mut buf = [0u8; 64];
    let mut f = match vol.open_file("/a long name.txt") {
        Ok(f) => f,
        Err(_) => loop {},
    };
    let n = f.read(&mut vol, &mut buf).unwrap_or(0);
    sink(n as u32);
    sink((buf[..n] == *body) as u32);

    // List the root: the iterator owns the name buffer, so this is a
    // `while let` rather than a `for`.
    let root = vol.root();
    let mut count = 0u32;
    let mut it = vol.iter_dir(root);
    while let Ok(Some(entry)) = it.next() {
        count += entry.name().len() as u32;
    }
    sink(count);
    drop(it);
    if vol.unmount().is_err() {
        loop {}
    }

    // The card reader's way: find out what is on the card, and use it
    // through the generic interface. `BLOCK` only matters with littlefs
    // compiled in, which this binary does not.
    let mut any = match fstool::fs::mount::<_, 512, 512>(RamCard) {
        Ok(v) => v,
        Err(_) => loop {},
    };
    sink(any.fs_type() as u32);
    sink(append_log(&mut any).unwrap_or(0));

    loop {}
}

/// Append a line to `/boot.log` and count the root's entries — on any
/// filesystem, written once.
fn append_log<V: fstool::fs::volume::Volume>(vol: &mut V) -> Result<u32, V::Error> {
    let mut log = vol.open_or_create_file("/boot.log")?;
    log.seek_to_end(vol)?;
    log.write_all(vol, b"booted\n")?;
    log.flush(vol)?;

    let root = vol.root();
    let mut it = vol.iter_dir(root);
    let mut entries = 0;
    while it.next()?.is_some() {
        entries += 1;
    }
    Ok(entries)
}
