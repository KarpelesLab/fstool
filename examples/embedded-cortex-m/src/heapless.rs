//! The same idea as `main.rs`, one step further down: **no allocator at
//! all**.
//!
//! There is no `extern crate alloc` and no `#[global_allocator]` here, and
//! fstool is pulled in with only `fat-noalloc`. If any reachable line of
//! the driver could allocate, this would not link — rustc refuses a binary
//! that needs the `alloc` crate without an allocator to back it. That
//! failure mode is the point of this program: it is a compile-time proof,
//! not a runtime demo.
//!
//! It formats a small FAT12 volume in a static RAM buffer (the formatter
//! is right here, since the no-alloc driver reads and writes volumes but
//! does not create them), then mounts it, writes a file, lists the root
//! and reads the file back.

#![no_std]
#![no_main]

use core::ptr;

use fstool::noalloc::fat::{FatKind, SectorDriver, Volume};

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

/// Lay out a FAT12 volume in the card buffer.
///
/// The driver mounts volumes rather than creating them, so a program that
/// must start from a blank medium brings its own layout — about fifty
/// lines, and only for the flavour it needs.
fn format_fat12(card: &mut [u8]) {
    const RESERVED: u32 = 1;
    const NUM_FATS: u32 = 2;
    const ROOT_ENTRIES: u32 = 512;
    const SPC: u32 = 1;
    let total = SECTORS as u32;
    let root_sectors = (ROOT_ENTRIES * 32).div_ceil(SECTOR as u32);

    // Size the FAT so it can map every cluster left over once it is
    // accounted for.
    let mut fat_sectors = 1u32;
    loop {
        let data = total - RESERVED - NUM_FATS * fat_sectors - root_sectors;
        let clusters = data / SPC;
        let need = (((clusters + 2).div_ceil(2) * 3) as u32).div_ceil(SECTOR as u32);
        if need <= fat_sectors {
            break;
        }
        fat_sectors = need;
    }

    card.fill(0);
    let boot = &mut card[..SECTOR];
    boot[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    boot[3..11].copy_from_slice(b"FSTOOL  ");
    boot[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    boot[13] = SPC as u8;
    boot[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    boot[16] = NUM_FATS as u8;
    boot[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    boot[19..21].copy_from_slice(&(total as u16).to_le_bytes());
    boot[21] = 0xF8;
    boot[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
    boot[510] = 0x55;
    boot[511] = 0xAA;

    // FAT[0] carries the media byte, FAT[1] ends a chain.
    for copy in 0..NUM_FATS {
        let at = (RESERVED + copy * fat_sectors) as usize * SECTOR;
        card[at] = 0xF8;
        card[at + 1] = 0xFF;
        card[at + 2] = 0xFF;
    }
}

// Pinned into its own section so the linker script can KEEP it: under
// `--gc-sections` an entry point nothing references is otherwise fair game.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.reset")]
pub extern "C" fn reset() -> ! {
    // SAFETY: single-threaded, and the reference is dropped before the
    // driver starts using the buffer.
    format_fat12(unsafe { &mut *ptr::addr_of_mut!(CARD) });

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

    loop {}
}
