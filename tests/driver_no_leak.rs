#![cfg(all(feature = "alloc", feature = "fat"))]
//! The allocator-free drivers hand their device back on `unmount`, which
//! means moving it out of a type that implements `Drop` — and that
//! suppresses the drop glue of every *other* field with it. Anything the
//! volume still owned at that moment is leaked.
//!
//! `alloc` is exactly when they own something: FAT keeps the allocation
//! table in memory, exFAT the up-case table, littlefs the volume's in-use
//! bitmap. So this test binary brings its own counting global allocator and
//! watches what a mount-touch-unmount cycle leaves behind — a thing no
//! assertion inside the library can see.
//!
//! It measures *per cycle* growth after a warm-up rather than one cycle
//! against zero: the harness itself allocates lazily — formatters,
//! thread-locals, a panic hook — and a few hundred bytes of that would
//! otherwise look like a finding. A leak scales with the number of cycles;
//! warm-up noise does not.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

/// Live bytes handed out by this binary's allocator.
static LIVE: AtomicIsize = AtomicIsize::new(0);

struct Counting;

// SAFETY: every method forwards to the system allocator unchanged; the
// counters are the only addition.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new) };
        if !q.is_null() {
            LIVE.fetch_add(new as isize - l.size() as isize, Ordering::Relaxed);
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

/// One counter, one test at a time: cargo runs the tests in this binary on
/// several threads, and another test's live allocations would otherwise look
/// like this one's leak.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Cycles measured per test.
const CYCLES: isize = 4;

/// Run a mount-touch-unmount cycle repeatedly and fail if what it leaves
/// behind grows with the number of runs.
///
/// `cycle` returns how many bytes of cache the volume was holding when it
/// was unmounted — what a leak would strand, and the scale the measurement
/// is judged against.
fn assert_no_leak(what: &str, mut cycle: impl FnMut() -> usize) {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // Warm-up: whatever the harness allocates lazily happens here.
    let held = cycle();
    assert!(
        held > 0,
        "{what}: the volume never populated its cache, so this proves nothing"
    );
    let before = live();
    for _ in 0..CYCLES {
        cycle();
    }
    let growth = live() - before;
    assert!(
        growth * 2 < held as isize * CYCLES,
        "{what}: {growth} bytes stayed live over {CYCLES} unmounts, each \
         holding {held} bytes of cache"
    );
}

/// A RAM card whose backing bytes are handed over, so the only allocation
/// left to account for is the volume's own.
struct Card(Vec<u8>);

impl fstool::device::SectorDriver for Card {
    type Error = std::convert::Infallible;

    fn sector_size(&self) -> u32 {
        512
    }

    fn sector_count(&self) -> u64 {
        self.0.len() as u64 / 512
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        let at = lba as usize * 512;
        buf.copy_from_slice(&self.0[at..at + buf.len()]);
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
        let at = lba as usize * 512;
        self.0[at..at + buf.len()].copy_from_slice(buf);
        Ok(())
    }
}

/// A FAT32 image with one file in it, built by the hosted writer.
fn fat_image() -> Vec<u8> {
    use fstool::block::MemoryBackend;
    use fstool::fs::fat::{Fat32, FatFormatOpts, FatKind};
    use fstool::fs::{FileMeta, FileSource, Filesystem};
    use fstool::path::Path;

    const SECTORS: u32 = 128 * 1024; // 64 MiB: comfortably FAT32
    let mut dev = MemoryBackend::new(SECTORS as u64 * 512);
    let opts = FatFormatOpts {
        kind: FatKind::Fat32,
        total_sectors: SECTORS,
        ..Default::default()
    };
    let mut fs = Fat32::format(&mut dev, &opts).expect("format");
    fs.create_file(
        &mut dev,
        Path::new("/payload.bin"),
        FileSource::Reader {
            reader: Box::new(std::io::Cursor::new(vec![0xa5u8; 200_000])),
            len: 200_000,
        },
        FileMeta::default(),
    )
    .expect("create");
    fs.flush(&mut dev).expect("flush");
    dev.into_bytes()
}

#[test]
fn fat_unmount_releases_the_allocation_table_cache() {
    let image = fat_image();
    assert_no_leak("fat", || {
        let mut vol = fstool::fs::fat::Volume::<_, 512>::mount(Card(image.clone())).expect("mount");
        // Walking the file is what fills the in-memory FAT.
        let mut f = vol.open_file("/payload.bin").expect("open");
        let mut buf = [0u8; 4096];
        while f.read(&mut vol, &mut buf).expect("read") > 0 {}
        let held = vol.fat_cache_bytes();
        drop(vol.unmount().expect("unmount"));
        held
    });
}

#[cfg(feature = "littlefs")]
#[test]
fn littlefs_unmount_releases_the_in_use_bitmap() {
    use fstool::device::FlashDriver;
    use fstool::fs::littlefs::Volume;

    /// 8192 blocks, so the volume's bitmap is a kilobyte — large enough to
    /// tell a leak from the harness's own noise.
    const BLOCKS: usize = 8192;

    struct Flash(Vec<u8>);
    impl FlashDriver for Flash {
        type Error = std::convert::Infallible;
        fn block_size(&self) -> u32 {
            4096
        }
        fn block_count(&self) -> u32 {
            (self.0.len() / 4096) as u32
        }
        fn read(&mut self, block: u32, off: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
            let at = block as usize * 4096 + off as usize;
            buf.copy_from_slice(&self.0[at..at + buf.len()]);
            Ok(())
        }
        fn prog(&mut self, block: u32, off: u32, data: &[u8]) -> Result<(), Self::Error> {
            let at = block as usize * 4096 + off as usize;
            self.0[at..at + data.len()].copy_from_slice(data);
            Ok(())
        }
        fn erase(&mut self, block: u32) -> Result<(), Self::Error> {
            let at = block as usize * 4096;
            self.0[at..at + 4096].fill(0xff);
            Ok(())
        }
    }

    assert_no_leak("littlefs", || {
        let mut vol =
            Volume::<_, 4096, 256>::format(Flash(vec![0xff; BLOCKS * 4096])).expect("format");
        // Writing is what builds the in-use bitmap.
        let mut f = vol.create_file("/payload.bin").expect("create");
        f.write_all(&mut vol, &[7u8; 40_000]).expect("write");
        let held = vol.alloc_cache_bytes();
        drop(vol.unmount().expect("unmount"));
        held
    });
}

#[cfg(feature = "exfat")]
#[test]
fn exfat_unmount_releases_the_upcase_table_cache() {
    use fstool::block::MemoryBackend;
    use fstool::fs::exfat::{Exfat, Volume, format::FormatOpts};

    let image = {
        let mut dev = MemoryBackend::new(24 * 1024 * 1024);
        let mut fs = Exfat::format(&mut dev, &FormatOpts::default()).expect("format");
        fs.flush(&mut dev).expect("flush");
        dev.into_bytes()
    };

    assert_no_leak("exfat", || {
        let mut vol = Volume::<_, 512>::mount(Card(image.clone())).expect("mount");
        let mut f = vol.create_file("/ünïcode.txt").expect("create");
        f.write_all(&mut vol, b"body").expect("write");
        f.flush(&mut vol).expect("flush");
        // Comparing a name outside ASCII is what decodes the up-case table
        // into memory — whether or not this volume's table folds those two
        // spellings, which is up to whatever formatted it.
        let _ = vol.exists("/ÜNÏCODE.TXT").expect("lookup");
        let held = vol.upcase_cache_bytes();
        drop(vol.unmount().expect("unmount"));
        held
    });
}
