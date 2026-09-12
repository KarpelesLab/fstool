//! Bare-metal smoke consumer: links fstool's FAT core for a Cortex-M4F with
//! no OS, no std, a bump allocator and a RAM-backed "SD card", to prove the
//! crate builds for the target and to measure the flash it costs.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;

use fstool::block::{BlockDevice, MemoryBackend};
use fstool::fs::fat::{Fat32, FatFormatOpts, FatKind};
use fstool::fs::{FileMeta, FileSource, Filesystem};
use fstool::io::Read;
use fstool::path::Path;

// ---- a 64 KiB bump allocator: enough for the FAT driver's tables --------
struct Bump(UnsafeCell<(usize, [u8; 64 * 1024])>);
unsafe impl Sync for Bump {}
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let s = unsafe { &mut *self.0.get() };
        let start = (s.0 + l.align() - 1) & !(l.align() - 1);
        let end = start + l.size();
        if end > s.1.len() {
            return ptr::null_mut();
        }
        s.0 = end;
        unsafe { s.1.as_mut_ptr().add(start) }
    }
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}
#[global_allocator]
static HEAP: Bump = Bump(UnsafeCell::new((0, [0; 64 * 1024])));

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Output sink the optimiser cannot see through, so the work stays.
#[inline(never)]
fn sink(v: u32) {
    unsafe { ptr::write_volatile(0x2000_0000 as *mut u32, v) }
}

#[unsafe(no_mangle)]
pub extern "C" fn reset() -> ! {
    // Format a 1 MiB FAT12 volume in RAM, add a file, list, read it back.
    let mut dev = MemoryBackend::new(1 << 20);
    let opts = FatFormatOpts {
        kind: FatKind::Fat12,
        total_sectors: 2048,
        ..Default::default()
    };
    let mut fs = Fat32::format(&mut dev, &opts).unwrap();
    let body: &[u8] = b"hello from a microcontroller";
    fs.create_file(
        &mut dev,
        Path::new("/HELLO.TXT"),
        FileSource::Reader {
            reader: alloc::boxed::Box::new(fstool::io::Cursor::new(body.to_vec())),
            len: body.len() as u64,
        },
        FileMeta::default(),
    )
    .unwrap();
    fs.flush(&mut dev).unwrap();
    dev.sync().unwrap();

    let mut fs = Fat32::open(&mut dev).unwrap();
    let entries = fs.list(&mut dev, Path::new("/")).unwrap();
    sink(entries.len() as u32);
    let mut out = Vec::new();
    fs.read_file(&mut dev, Path::new("/HELLO.TXT"))
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    sink(out.len() as u32);
    loop {}
}
