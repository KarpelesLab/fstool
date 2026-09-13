//! The same idea as `heapless.rs`, on flash instead of a card: littlefs
//! with **no allocator at all**.
//!
//! There is no `extern crate alloc` and no `#[global_allocator]` here, and
//! fstool is pulled in with `littlefs` but not `alloc`. If any reachable
//! line of the driver could allocate, this would not link — rustc refuses a
//! binary that needs the `alloc` crate without an allocator to back it.
//! That failure mode is the point of this program: it is a compile-time
//! proof, not a runtime demo.
//!
//! Unlike the FAT one, it needs no formatter of its own — the littlefs
//! driver lays down a volume itself, since a littlefs format is a single
//! metadata commit rather than a table layout.

#![no_std]
#![no_main]

use core::ptr;

use fstool::device::FlashDriver;
use fstool::fs::littlefs::Volume;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Output sink the optimiser cannot see through, so the work stays.
#[inline(never)]
fn sink(v: u32) {
    unsafe { ptr::write_volatile(0x2000_0000 as *mut u32, v) }
}

/// 128 KiB of "NOR flash": 32 blocks of 4 KiB.
const BLOCK_SIZE: usize = 4096;
const BLOCKS: usize = 32;

/// The flash: one static buffer, no heap. Zero-initialised so it lands in
/// `.bss` rather than in the firmware image — the driver erases every block
/// before it programs one, which is exactly what it has to do on real
/// hardware whose contents it did not put there.
static mut FLASH: [u8; BLOCKS * BLOCK_SIZE] = [0; BLOCKS * BLOCK_SIZE];

/// A [`FlashDriver`] over that buffer. A real program implements these
/// methods against its QSPI/SPI-NOR peripheral instead.
struct RamFlash;

impl FlashDriver for RamFlash {
    type Error = core::convert::Infallible;

    fn block_size(&self) -> u32 {
        BLOCK_SIZE as u32
    }

    fn block_count(&self) -> u32 {
        BLOCKS as u32
    }

    fn prog_size(&self) -> u32 {
        256
    }

    fn read(&mut self, block: u32, off: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        let at = block as usize * BLOCK_SIZE + off as usize;
        // SAFETY: single-threaded bare-metal program; the flash is touched
        // only through this driver.
        let flash = unsafe { &*ptr::addr_of!(FLASH) };
        buf.copy_from_slice(&flash[at..at + buf.len()]);
        Ok(())
    }

    fn prog(&mut self, block: u32, off: u32, data: &[u8]) -> Result<(), Self::Error> {
        let at = block as usize * BLOCK_SIZE + off as usize;
        // SAFETY: as above.
        let flash = unsafe { &mut *ptr::addr_of_mut!(FLASH) };
        // Real NOR can only clear bits; the AND is what the hardware does.
        for (slot, byte) in flash[at..at + data.len()].iter_mut().zip(data) {
            *slot &= *byte;
        }
        Ok(())
    }

    fn erase(&mut self, block: u32) -> Result<(), Self::Error> {
        let at = block as usize * BLOCK_SIZE;
        // SAFETY: as above.
        let flash = unsafe { &mut *ptr::addr_of_mut!(FLASH) };
        flash[at..at + BLOCK_SIZE].fill(0xff);
        Ok(())
    }
}

// Pinned into its own section so the linker script can KEEP it: under
// `--gc-sections` an entry point nothing references is otherwise fair game.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.reset")]
pub extern "C" fn reset() -> ! {
    // One block of scratch (4 KiB) plus a page of staging (256 B) is the
    // driver's entire footprint.
    let mut vol = match Volume::<_, 4096, 256>::format(RamFlash) {
        Ok(v) => v,
        Err(_) => loop {},
    };
    sink(vol.geometry().block_count);
    sink(vol.free_blocks().unwrap_or(0));

    // A directory, a file inside it, and a timestamp in a user attribute —
    // which is where an embedded program keeps one, littlefs having no
    // metadata of its own.
    if vol.create_dir("/log").is_err() {
        loop {}
    }
    let body: &[u8] = b"hello from a microcontroller, with no heap";
    let mut f = match vol.create_file("/log/boot.txt") {
        Ok(f) => f,
        Err(_) => loop {},
    };
    if f.write_all(&mut vol, body).is_err() {
        loop {}
    }
    if vol.set_attr("/log/boot.txt", 1, &1_700_000_000u32.to_le_bytes()).is_err() {
        loop {}
    }

    // Read it back.
    let mut buf = [0u8; 64];
    let mut f = match vol.open_file("/log/boot.txt") {
        Ok(f) => f,
        Err(_) => loop {},
    };
    let n = f.read(&mut vol, &mut buf).unwrap_or(0);
    sink(n as u32);
    sink((buf[..n] == *body) as u32);

    // List a directory: entries borrow the volume's scratch, so this is a
    // `while let` rather than a `for`.
    let dir = match vol.open_dir("/log") {
        Ok(d) => d,
        Err(_) => loop {},
    };
    let mut names = 0u32;
    let mut it = vol.iter_dir(dir);
    while let Ok(Some(entry)) = it.next() {
        names += entry.name().len() as u32;
    }
    sink(names);

    // And the volume still mounts from scratch, which is what a reboot does.
    let flash = match vol.unmount() {
        Ok(f) => f,
        Err(_) => loop {},
    };
    let mut vol = match Volume::<_, 4096, 256>::mount(flash) {
        Ok(v) => v,
        Err(_) => loop {},
    };
    sink(vol.metadata("/log/boot.txt").map(|m| m.len()).unwrap_or(0));

    loop {}
}
