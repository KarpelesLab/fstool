//! Tests for the allocator-free littlefs driver.
//!
//! These run in every configuration, including `--no-default-features
//! --features littlefs`, the heapless one: the driver formats the volumes
//! itself, so nothing here needs [`crate::fs::littlefs::LittleFs`], which
//! that configuration does not compile. Where the hosted half *is*
//! available, the `cross` module at the end plays the two against each
//! other — the strongest evidence that this driver agrees with something
//! independently validated against the C implementation.

use alloc::vec;
use alloc::vec::Vec;

use super::*;

/// A RAM-backed flash that holds the driver to the contract it promises:
/// reads and programs stay inside a block, programs are whole pages, and
/// nothing is programmed twice without an erase in between.
#[derive(Debug)]
struct RamFlash {
    data: Vec<u8>,
    block_size: u32,
    prog_size: u32,
    reads: u32,
    progs: u32,
    erases: u32,
}

impl RamFlash {
    fn new(blocks: u32, block_size: u32) -> Self {
        Self {
            data: vec![0xff; (blocks * block_size) as usize],
            block_size,
            prog_size: 256,
            reads: 0,
            progs: 0,
            erases: 0,
        }
    }

    fn with_prog_size(mut self, prog: u32) -> Self {
        self.prog_size = prog;
        self
    }

    fn counters(&mut self) {
        self.reads = 0;
        self.progs = 0;
        self.erases = 0;
    }
}

impl FlashDriver for RamFlash {
    type Error = core::convert::Infallible;

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn block_count(&self) -> u32 {
        (self.data.len() / self.block_size as usize) as u32
    }

    fn prog_size(&self) -> u32 {
        self.prog_size
    }

    fn read(&mut self, block: u32, off: u32, buf: &mut [u8]) -> Result<(), Self::Error> {
        assert!(block < self.block_count(), "read past the end of the flash");
        assert!(
            off as usize + buf.len() <= self.block_size as usize,
            "read ran out of block {block}"
        );
        self.reads += 1;
        let at = block as usize * self.block_size as usize + off as usize;
        buf.copy_from_slice(&self.data[at..at + buf.len()]);
        Ok(())
    }

    fn prog(&mut self, block: u32, off: u32, data: &[u8]) -> Result<(), Self::Error> {
        assert!(block < self.block_count(), "prog past the end of the flash");
        assert!(
            off as usize + data.len() <= self.block_size as usize,
            "prog ran out of block {block}"
        );
        assert_eq!(off % self.prog_size, 0, "prog at an unaligned offset");
        assert_eq!(
            data.len() as u32 % self.prog_size,
            0,
            "prog of a partial page"
        );
        self.progs += 1;
        let at = block as usize * self.block_size as usize + off as usize;
        for (i, b) in data.iter().enumerate() {
            assert_eq!(
                self.data[at + i],
                0xff,
                "programming byte {i} of block {block} at {off}, which is not erased"
            );
            self.data[at + i] = *b;
        }
        Ok(())
    }

    fn erase(&mut self, block: u32) -> Result<(), Self::Error> {
        assert!(
            block < self.block_count(),
            "erase past the end of the flash"
        );
        self.erases += 1;
        let at = block as usize * self.block_size as usize;
        self.data[at..at + self.block_size as usize].fill(0xff);
        Ok(())
    }
}

type Vol = Volume<RamFlash, 4096, 256>;
type SmallVol = Volume<RamFlash, 512, 16>;

/// A formatted 256 KiB volume: 64 blocks of 4 KiB.
fn fresh() -> Vol {
    Volume::format(RamFlash::new(64, 4096)).expect("format")
}

/// A formatted volume with 512-byte blocks, where metadata pairs fill up
/// after a handful of entries.
fn fresh_small(blocks: u32) -> SmallVol {
    Volume::format(RamFlash::new(blocks, 512).with_prog_size(16)).expect("format")
}

/// Unmount and mount again, so every test can check that what it wrote is
/// what a fresh mount sees.
fn remount<const B: usize, const P: usize>(vol: Volume<RamFlash, B, P>) -> Volume<RamFlash, B, P> {
    let flash = vol.unmount().expect("unmount");
    Volume::mount(flash).expect("remount")
}

/// Every name in a directory, in listing order.
fn list<const B: usize, const P: usize>(
    vol: &mut Volume<RamFlash, B, P>,
    path: &str,
) -> Vec<Vec<u8>> {
    let dir = vol.open_dir(path).expect("open_dir");
    let mut out = Vec::new();
    let mut it = vol.iter_dir(dir);
    while let Some(e) = it.next().expect("iter") {
        out.push(e.name().to_vec());
    }
    out
}

fn read_all<const B: usize, const P: usize>(
    vol: &mut Volume<RamFlash, B, P>,
    path: &str,
) -> Vec<u8> {
    let mut f = vol.open_file(path).expect("open_file");
    let mut out = vec![0u8; f.len() as usize];
    f.read_exact(vol, &mut out).expect("read_exact");
    out
}

fn write_file<const B: usize, const P: usize>(
    vol: &mut Volume<RamFlash, B, P>,
    path: &str,
    body: &[u8],
) {
    let mut f = vol.open_or_create_file(path).expect("create");
    f.set_len(vol, 0).expect("truncate");
    f.write_all(vol, body).expect("write");
}

#[test]
fn a_fresh_volume_mounts_and_is_empty() {
    let mut vol = fresh();
    assert_eq!(vol.geometry().block_size, 4096);
    assert_eq!(vol.geometry().block_count, 64);
    assert_eq!(vol.geometry().version_parts(), (2, 1));
    assert!(list(&mut vol, "/").is_empty());
    // The superblock pair, and nothing else.
    assert_eq!(vol.used_blocks().unwrap(), 2);

    let mut vol = remount(vol);
    assert!(list(&mut vol, "/").is_empty());
    assert!(vol.metadata("/").unwrap().is_dir());
}

#[test]
fn an_unformatted_flash_is_refused() {
    let flash = RamFlash::new(16, 4096);
    assert!(matches!(
        Volume::<_, 4096>::mount(flash),
        Err(Error::NotLittleFs)
    ));
}

#[test]
fn scratch_smaller_than_a_block_is_refused() {
    // 512 bytes of scratch cannot hold a 4 KiB metadata block.
    let flash = RamFlash::new(16, 4096);
    assert!(matches!(
        Volume::<_, 512, 256>::format(flash),
        Err(Error::ScratchTooSmall {
            needed: 4096,
            got: 512
        })
    ));
    // Nor can a 16-byte staging buffer hold a 256-byte program page.
    let flash = RamFlash::new(16, 4096);
    assert!(matches!(
        Volume::<_, 4096, 16>::format(flash),
        Err(Error::ScratchTooSmall {
            needed: 256,
            got: 16
        })
    ));
}

#[test]
fn a_small_file_rides_inline_in_the_metadata() {
    let mut vol = fresh();
    let body = b"small enough to live in its directory";
    write_file(&mut vol, "/hello.txt", body);
    let f = vol.open_file("/hello.txt").unwrap();
    assert!(f.is_inline(), "a 37-byte file should be inline");
    // No data block was needed: still just the superblock pair.
    assert_eq!(vol.used_blocks().unwrap(), 2);

    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/hello.txt"), body);
    assert_eq!(vol.metadata("/hello.txt").unwrap().len(), body.len() as u32);
    assert!(vol.metadata("/hello.txt").unwrap().is_file());
}

#[test]
fn a_large_file_becomes_a_skip_list() {
    let mut vol = fresh();
    let body: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    write_file(&mut vol, "/big.bin", &body);
    let f = vol.open_file("/big.bin").unwrap();
    assert!(!f.is_inline(), "a 40 KB file cannot be inline");
    assert_eq!(f.len(), body.len() as u32);

    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/big.bin"), body);
    // Reading in awkward-sized bites must give the same bytes.
    let mut f = vol.open_file("/big.bin").unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 999];
    loop {
        let n = f.read(&mut vol, &mut buf).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    assert_eq!(out, body);
}

#[test]
fn appending_grows_a_file_through_both_shapes() {
    let mut vol = fresh();
    let mut f = vol.create_file("/log.txt").unwrap();
    let mut expect = Vec::new();
    for i in 0..40u32 {
        let line = alloc::format!("line {i} of a log that outgrows its metadata block\n");
        f.seek_to_end(&mut vol);
        f.write_all(&mut vol, line.as_bytes()).unwrap();
        expect.extend_from_slice(line.as_bytes());
        assert_eq!(f.len(), expect.len() as u32);
    }
    assert!(!f.is_inline(), "the log should have been outlined by now");

    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/log.txt"), expect);
}

#[test]
fn writing_in_the_middle_keeps_the_rest() {
    let mut vol = fresh();
    let mut body: Vec<u8> = (0..30_000u32).map(|i| (i % 97) as u8).collect();
    write_file(&mut vol, "/patch.bin", &body);

    let mut f = vol.open_file("/patch.bin").unwrap();
    f.seek(12_345);
    f.write_all(&mut vol, b"PATCHED").unwrap();
    body[12_345..12_352].copy_from_slice(b"PATCHED");

    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/patch.bin"), body);
}

#[test]
fn seeking_past_the_end_zero_fills() {
    let mut vol = fresh();
    let mut f = vol.create_file("/sparse.bin").unwrap();
    f.write_all(&mut vol, b"start").unwrap();
    f.seek(10_000);
    f.write_all(&mut vol, b"end").unwrap();
    assert_eq!(f.len(), 10_003);

    let mut vol = remount(vol);
    let got = read_all(&mut vol, "/sparse.bin");
    assert_eq!(&got[..5], b"start");
    assert!(
        got[5..10_000].iter().all(|b| *b == 0),
        "the gap is not zeros"
    );
    assert_eq!(&got[10_000..], b"end");
}

#[test]
fn set_len_truncates_and_gives_the_blocks_back() {
    let mut vol = fresh();
    let body: Vec<u8> = (0..50_000u32).map(|i| (i % 211) as u8).collect();
    write_file(&mut vol, "/shrink.bin", &body);
    let before = vol.used_blocks().unwrap();

    let mut f = vol.open_file("/shrink.bin").unwrap();
    f.set_len(&mut vol, 5_000).unwrap();
    assert_eq!(f.len(), 5_000);
    let after = vol.used_blocks().unwrap();
    assert!(
        after < before,
        "truncation kept {after} blocks of the {before} it had"
    );

    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/shrink.bin"), body[..5_000]);

    // And all the way down to nothing.
    let mut f = vol.open_file("/shrink.bin").unwrap();
    f.set_len(&mut vol, 0).unwrap();
    assert_eq!(f.len(), 0);
    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/shrink.bin"), Vec::<u8>::new());
    assert_eq!(vol.used_blocks().unwrap(), 2);
}

#[test]
fn set_len_extends_with_zeros() {
    let mut vol = fresh();
    let mut f = vol.create_file("/grow.bin").unwrap();
    f.write_all(&mut vol, b"abc").unwrap();
    f.set_len(&mut vol, 9_000).unwrap();

    let mut vol = remount(vol);
    let got = read_all(&mut vol, "/grow.bin");
    assert_eq!(got.len(), 9_000);
    assert_eq!(&got[..3], b"abc");
    assert!(got[3..].iter().all(|b| *b == 0));
}

#[test]
fn directories_nest_and_list() {
    let mut vol = fresh();
    vol.create_dir("/etc").unwrap();
    vol.create_dir("/etc/ssl").unwrap();
    write_file(
        &mut vol,
        "/etc/ssl/cert.pem",
        b"----- not really a cert -----",
    );
    write_file(&mut vol, "/etc/hostname", b"device-1\n");

    let mut vol = remount(vol);
    assert_eq!(list(&mut vol, "/"), [b"etc".to_vec()]);
    assert_eq!(
        list(&mut vol, "/etc"),
        [b"hostname".to_vec(), b"ssl".to_vec()],
        "entries are sorted by their raw name bytes"
    );
    assert_eq!(list(&mut vol, "/etc/ssl"), [b"cert.pem".to_vec()]);
    assert!(vol.metadata("/etc/ssl").unwrap().is_dir());
    assert_eq!(read_all(&mut vol, "/etc/hostname"), b"device-1\n");

    // Paths behave the way littlefs's own walk does.
    assert!(vol.exists("etc/hostname").unwrap());
    assert!(vol.exists("//etc//ssl/").unwrap());
    assert!(!vol.exists("/etc/nope").unwrap());
    assert!(matches!(vol.metadata("/etc/./x"), Err(Error::InvalidPath)));
}

#[test]
fn creating_something_twice_is_refused() {
    let mut vol = fresh();
    vol.create_dir("/a").unwrap();
    assert!(matches!(vol.create_dir("/a"), Err(Error::AlreadyExists)));
    vol.create_file("/a/f").unwrap();
    assert!(matches!(vol.create_file("/a/f"), Err(Error::AlreadyExists)));
    assert!(matches!(vol.open_file("/a"), Err(Error::IsADirectory)));
    assert!(matches!(vol.open_dir("/a/f"), Err(Error::NotADirectory)));
    assert!(vol.open_file("/a/missing").unwrap_err().is_not_found());
    assert!(matches!(vol.create_file("/nodir/f"), Err(Error::NotFound)));
}

#[test]
fn removing_files_and_directories() {
    let mut vol = fresh();
    vol.create_dir("/d").unwrap();
    write_file(&mut vol, "/d/big.bin", &vec![7u8; 20_000]);
    write_file(&mut vol, "/d/small", b"x");

    assert!(matches!(
        vol.remove_dir("/d"),
        Err(Error::DirectoryNotEmpty)
    ));
    assert!(matches!(vol.remove_file("/d"), Err(Error::IsADirectory)));
    assert!(matches!(
        vol.remove_dir("/d/small"),
        Err(Error::NotADirectory)
    ));

    vol.remove_file("/d/big.bin").unwrap();
    vol.remove_file("/d/small").unwrap();
    assert!(list(&mut vol, "/d").is_empty());
    vol.remove_dir("/d").unwrap();

    let mut vol = remount(vol);
    assert!(list(&mut vol, "/").is_empty());
    assert_eq!(
        vol.used_blocks().unwrap(),
        2,
        "removing everything should leave only the superblock pair"
    );
}

#[test]
fn the_space_a_removed_file_used_is_handed_out_again() {
    // Bigger than half the volume, so the second write can only succeed if
    // the first file's blocks really came back.
    let mut vol = fresh();
    let body = vec![0xa5u8; 150_000];
    write_file(&mut vol, "/one.bin", &body);
    vol.remove_file("/one.bin").unwrap();
    write_file(&mut vol, "/two.bin", &body);
    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/two.bin"), body);
}

#[test]
fn a_directory_grows_past_its_first_metadata_pair() {
    // 512-byte blocks: a pair holds only a few entries before it splits.
    let mut vol = fresh_small(64);
    let mut names = Vec::new();
    for i in 0..40u32 {
        let name = alloc::format!("/entry-{i:03}");
        write_file(&mut vol, &name, alloc::format!("body {i}").as_bytes());
        names.push(name.as_bytes()[1..].to_vec());
    }
    names.sort();

    let mut vol = remount(vol);
    assert_eq!(list(&mut vol, "/"), names);
    for i in 0..40u32 {
        assert_eq!(
            read_all(&mut vol, &alloc::format!("/entry-{i:03}")),
            alloc::format!("body {i}").as_bytes()
        );
    }
    // Every entry must still be findable by name, which is what a split
    // chain can quietly break.
    assert!(vol.exists("/entry-039").unwrap());
    vol.remove_file("/entry-020").unwrap();
    assert!(!vol.exists("/entry-020").unwrap());
    assert!(vol.exists("/entry-021").unwrap());
}

#[test]
fn a_name_at_the_limit_works_and_one_past_it_does_not() {
    let mut vol = fresh();
    let name: alloc::string::String = core::iter::repeat_n('n', 255).collect();
    write_file(&mut vol, &alloc::format!("/{name}"), b"at the limit");
    let too_long: alloc::string::String = core::iter::repeat_n('n', 256).collect();
    assert!(matches!(
        vol.create_file(&alloc::format!("/{too_long}")),
        Err(Error::InvalidName)
    ));

    let mut vol = remount(vol);
    assert_eq!(list(&mut vol, "/"), [name.as_bytes().to_vec()]);
}

#[test]
fn running_out_of_space_is_reported() {
    let mut vol = fresh_small(8);
    let mut f = vol.create_file("/hog.bin").unwrap();
    let chunk = vec![3u8; 512];
    let mut err = None;
    for _ in 0..64 {
        if let Err(e) = f.write_all(&mut vol, &chunk) {
            err = Some(e);
            break;
        }
    }
    assert!(
        matches!(err, Some(Error::NoSpace)),
        "filling a tiny volume reported {err:?}"
    );
    // And the volume is still usable afterwards.
    let mut vol = remount(vol);
    assert!(vol.exists("/hog.bin").unwrap());
}

#[test]
fn user_attributes_round_trip() {
    let mut vol = fresh();
    write_file(&mut vol, "/f", b"body");
    vol.set_attr("/f", 1, b"1700000000").unwrap();
    vol.set_attr("/f", 9, &[0xde, 0xad]).unwrap();

    let mut vol = remount(vol);
    let mut buf = [0u8; 32];
    assert_eq!(vol.attr("/f", 1, &mut buf).unwrap(), 10);
    assert_eq!(&buf[..10], b"1700000000");
    assert_eq!(vol.attr("/f", 9, &mut buf).unwrap(), 2);
    assert_eq!(&buf[..2], &[0xde, 0xad]);
    assert!(vol.attr("/f", 2, &mut buf).unwrap_err().is_not_found());
    // The file itself is untouched by all of that.
    assert_eq!(read_all(&mut vol, "/f"), b"body");

    // A short buffer takes what fits, as getxattr does.
    let mut small = [0u8; 4];
    assert_eq!(vol.attr("/f", 1, &mut small).unwrap(), 10);
    assert_eq!(&small, b"1700");

    vol.remove_attr("/f", 1).unwrap();
    let mut vol = remount(vol);
    assert!(vol.attr("/f", 1, &mut buf).unwrap_err().is_not_found());
    assert_eq!(vol.attr("/f", 9, &mut buf).unwrap(), 2);
    assert_eq!(read_all(&mut vol, "/f"), b"body");
}

#[test]
fn attributes_survive_an_entry_moving_between_pairs() {
    // Entries shift between pairs as a directory splits; an attribute has to
    // travel with its entry.
    let mut vol = fresh_small(64);
    for i in 0..24u32 {
        let name = alloc::format!("/e{i:02}");
        write_file(&mut vol, &name, b"x");
        vol.set_attr(&name, 7, alloc::format!("attr-{i:02}").as_bytes())
            .unwrap();
    }
    let mut vol = remount(vol);
    let mut buf = [0u8; 16];
    for i in 0..24u32 {
        let name = alloc::format!("/e{i:02}");
        let n = vol.attr(&name, 7, &mut buf).unwrap();
        assert_eq!(
            &buf[..n],
            alloc::format!("attr-{i:02}").as_bytes(),
            "{name}"
        );
    }
}

#[test]
fn a_volume_with_byte_addressable_storage_works_too() {
    // prog_size 1: every commit is padded to a single byte, which is the
    // configuration a file-backed or RAM-backed store has.
    let flash = RamFlash::new(32, 512).with_prog_size(1);
    let mut vol = Volume::<_, 512, 256>::format(flash).unwrap();
    write_file(&mut vol, "/a", b"one");
    vol.create_dir("/d").unwrap();
    write_file(&mut vol, "/d/b", &vec![1u8; 4_000]);
    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/a"), b"one");
    assert_eq!(read_all(&mut vol, "/d/b"), vec![1u8; 4_000]);
}

#[test]
fn a_volume_pinned_to_disk_version_2_0_carries_no_forward_crc() {
    let opts = FormatOpts {
        disk_version: crate::fs::littlefs::DISK_VERSION_2_0,
        ..FormatOpts::default()
    };
    let mut vol = Volume::<_, 4096, 256>::format_with(RamFlash::new(16, 4096), &opts).unwrap();
    assert_eq!(vol.geometry().version_parts(), (2, 0));
    write_file(&mut vol, "/a", b"two-oh");
    let mut vol = remount(vol);
    assert_eq!(vol.geometry().version_parts(), (2, 0));
    assert_eq!(read_all(&mut vol, "/a"), b"two-oh");
}

#[test]
fn a_corrupt_live_block_falls_back_to_its_partner() {
    let mut vol = fresh();
    write_file(&mut vol, "/keep", b"survivor");
    // Scribble over the live half of the root pair. Its partner still holds
    // the commit before it, which is the guarantee a metadata *pair* makes.
    let root = vol.root().pair();
    {
        let bs = vol.geometry().block_size as usize;
        let flash = vol.driver_mut();
        let at = root[0] as usize * bs;
        flash.data[at..at + 64].fill(0);
    }
    let mut vol = remount(vol);
    // Either the file is there (the scribbled block was the stale half) or
    // the volume fell back to the commit before it — never a failed mount.
    let names = list(&mut vol, "/");
    assert!(names.is_empty() || names == [b"keep".to_vec()], "{names:?}");
}

#[test]
fn allocation_does_not_hand_the_same_block_out_twice() {
    // A write large enough to need many blocks, on a volume small enough
    // that the lookahead window is refilled part-way through it. Two files
    // sharing a block would show up as one of them reading back wrong.
    let mut vol = fresh_small(200);
    let a = vec![0x11u8; 20_000];
    let b = vec![0x22u8; 20_000];
    write_file(&mut vol, "/a.bin", &a);
    write_file(&mut vol, "/b.bin", &b);
    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/a.bin"), a);
    assert_eq!(read_all(&mut vol, "/b.bin"), b);
}

#[test]
fn a_commit_costs_one_erase_and_one_block() {
    let mut vol = fresh();
    write_file(&mut vol, "/f", b"body");
    vol.driver_mut().counters();
    // Setting an attribute is one metadata commit: one erase, and programs
    // that add up to no more than a block.
    vol.set_attr("/f", 3, b"v").unwrap();
    let flash = vol.driver();
    assert_eq!(flash.erases, 1, "a commit should erase exactly one block");
    assert!(
        flash.progs <= 4096 / 256,
        "{} programs for one commit",
        flash.progs
    );
}

#[test]
fn the_allocation_cache_only_changes_how_much_is_read() {
    // With `alloc` the whole volume's bitmap is held; without it, the
    // lookahead window is refilled by traversal. Same answers either way.
    let mut vol = fresh();
    write_file(&mut vol, "/f.bin", &vec![9u8; 30_000]);
    let used = vol.used_blocks().unwrap();
    assert!(used > 2);
    if cfg!(feature = "alloc") {
        assert!(
            vol.alloc_cache_bytes() > 0,
            "the bitmap should be held with a heap"
        );
    } else {
        assert_eq!(vol.alloc_cache_bytes(), 0);
    }
    assert_eq!(vol.free_blocks().unwrap(), 64 - used);
}

// ---------------------------------------------------------------------
// Cross-checks against the hosted half, which exists only with `alloc`.
// ---------------------------------------------------------------------

#[cfg(feature = "alloc")]
mod cross {
    use super::*;
    use crate::block::{BlockDevice, MemoryBackend};
    use crate::fs::littlefs::{LittleFs, LittleFsFormatOpts};
    use crate::fs::{FileMeta, FileSource, Filesystem};
    use crate::io::Cursor;
    use crate::path::Path;
    use alloc::boxed::Box;
    use alloc::string::String;

    const BLOCKS: u32 = 64;
    const BLOCK_SIZE: u32 = 4096;

    fn hosted_format() -> MemoryBackend {
        let mut dev = MemoryBackend::new((BLOCKS * BLOCK_SIZE) as u64);
        let opts = LittleFsFormatOpts {
            block_size: BLOCK_SIZE,
            block_count: Some(BLOCKS),
            prog_size: 256,
            ..Default::default()
        };
        let mut fs = LittleFs::format(&mut dev, &opts).expect("hosted format");
        fs.flush(&mut dev).expect("hosted flush");
        dev
    }

    fn hosted_write(fs: &mut LittleFs, dev: &mut MemoryBackend, path: &str, body: &[u8]) {
        fs.create_file(
            dev,
            Path::new(path),
            FileSource::Reader {
                reader: Box::new(Cursor::new(body.to_vec())),
                len: body.len() as u64,
            },
            FileMeta::default(),
        )
        .expect("hosted create_file");
    }

    fn hosted_read(fs: &mut LittleFs, dev: &mut MemoryBackend, path: &str) -> Vec<u8> {
        use crate::io::Read;
        let mut out = Vec::new();
        let mut r = fs.read_file(dev, Path::new(path)).expect("hosted read");
        let mut buf = [0u8; 4096];
        loop {
            let n = r.read(&mut buf).expect("hosted read chunk");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    fn as_flash(dev: MemoryBackend) -> RamFlash {
        let mut flash = RamFlash::new(BLOCKS, BLOCK_SIZE);
        flash.data = dev.into_bytes();
        flash
    }

    #[test]
    fn reads_a_volume_the_hosted_half_wrote() {
        let mut dev = hosted_format();
        let mut fs = LittleFs::open(&mut dev).unwrap();
        fs.create_dir(&mut dev, Path::new("/sub"), FileMeta::default())
            .unwrap();
        let big: Vec<u8> = (0..30_000u32).map(|i| (i % 241) as u8).collect();
        hosted_write(&mut fs, &mut dev, "/sub/big.bin", &big);
        hosted_write(&mut fs, &mut dev, "/sub/inline.txt", b"tiny");
        fs.flush(&mut dev).unwrap();

        let mut vol = Volume::<_, 4096, 256>::mount(as_flash(dev)).expect("driver mount");
        assert_eq!(list(&mut vol, "/"), [b"sub".to_vec()]);
        assert_eq!(
            list(&mut vol, "/sub"),
            [b"big.bin".to_vec(), b"inline.txt".to_vec()]
        );
        assert_eq!(read_all(&mut vol, "/sub/big.bin"), big);
        assert_eq!(read_all(&mut vol, "/sub/inline.txt"), b"tiny");
    }

    #[test]
    fn the_hosted_half_reads_what_the_driver_wrote() {
        let mut vol = Volume::<_, 4096, 256>::mount(as_flash(hosted_format())).unwrap();
        vol.create_dir("/from-driver").unwrap();
        let body: Vec<u8> = (0..45_000u32).map(|i| (i % 253) as u8).collect();
        write_file(&mut vol, "/from-driver/payload.bin", &body);
        write_file(&mut vol, "/from-driver/note.txt", b"written with no heap");
        vol.set_attr("/from-driver/note.txt", 4, b"attr").unwrap();
        let flash = vol.unmount().unwrap();

        // Read it back with the half CI validates against `littlefs-python`.
        let mut dev = MemoryBackend::from_bytes(flash.data);
        let mut fs = LittleFs::open(&mut dev).expect("hosted open");
        let listing = fs.list(&mut dev, Path::new("/from-driver")).unwrap();
        let names: Vec<String> = listing.iter().map(|e| e.name.clone()).collect();
        assert_eq!(names, ["note.txt", "payload.bin"]);
        assert_eq!(
            hosted_read(&mut fs, &mut dev, "/from-driver/payload.bin"),
            body
        );
        assert_eq!(
            hosted_read(&mut fs, &mut dev, "/from-driver/note.txt"),
            b"written with no heap"
        );
        let xattrs = fs
            .list_xattrs(&mut dev, Path::new("/from-driver/note.txt"))
            .unwrap();
        assert!(
            xattrs
                .iter()
                .any(|x| x.name == "user.littlefs.4" && x.value == b"attr"),
            "{xattrs:?}"
        );
    }

    #[test]
    fn both_halves_agree_after_interleaved_edits() {
        // The driver creates, the hosted half adds beside it, then the
        // driver removes — and both listings have to match.
        let mut vol = Volume::<_, 4096, 256>::mount(as_flash(hosted_format())).unwrap();
        for i in 0..6u32 {
            write_file(&mut vol, &alloc::format!("/d{i}.bin"), &vec![i as u8; 600]);
        }
        let flash = vol.unmount().unwrap();

        let mut dev = MemoryBackend::from_bytes(flash.data);
        let mut fs = LittleFs::open(&mut dev).unwrap();
        hosted_write(&mut fs, &mut dev, "/hosted.bin", &vec![0xee; 9_000]);
        fs.remove(&mut dev, Path::new("/d3.bin")).unwrap();
        fs.flush(&mut dev).unwrap();
        let bytes = {
            let mut out = vec![0u8; (BLOCKS * BLOCK_SIZE) as usize];
            dev.read_at(0, &mut out).unwrap();
            out
        };

        let mut flash = RamFlash::new(BLOCKS, BLOCK_SIZE);
        flash.data = bytes;
        let mut vol = Volume::<_, 4096, 256>::mount(flash).unwrap();
        let names = list(&mut vol, "/");
        assert!(names.iter().any(|n| n == b"hosted.bin"), "{names:?}");
        assert!(!names.iter().any(|n| n == b"d3.bin"), "{names:?}");
        assert_eq!(read_all(&mut vol, "/hosted.bin"), vec![0xee; 9_000]);
        assert_eq!(read_all(&mut vol, "/d0.bin"), vec![0u8; 600]);

        vol.remove_file("/d5.bin").unwrap();
        write_file(&mut vol, "/after.txt", b"last word");
        let flash = vol.unmount().unwrap();

        let mut dev = MemoryBackend::from_bytes(flash.data);
        let mut fs = LittleFs::open(&mut dev).unwrap();
        let listing = fs.list(&mut dev, Path::new("/")).unwrap();
        let names: Vec<String> = listing.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains(&String::from("after.txt")), "{names:?}");
        assert!(!names.contains(&String::from("d5.bin")), "{names:?}");
        assert_eq!(hosted_read(&mut fs, &mut dev, "/after.txt"), b"last word");
    }
}

// ---------------------------------------------------------------------
// Reading logs this driver never writes.
//
// Both halves of fstool rewrite a metadata pair whole, so neither produces
// a block whose log holds several commits with overrides and splices in it.
// A stock littlefs does, constantly, and reading those is the whole point of
// the backwards tag walk — so the shape is built here by hand.
// ---------------------------------------------------------------------

/// Append a tag and its data to a commit under construction.
fn push_tag(buf: &mut Vec<u8>, ptag: &mut u32, t: tag::Tag, data: &[u8]) {
    let stored = (t.0 & 0x7fff_ffff) ^ *ptag;
    buf.extend_from_slice(&stored.to_be_bytes());
    buf.extend_from_slice(data);
    *ptag = t.0 & 0x7fff_ffff;
}

/// Close a commit: the CRC tag, then the checksum of everything in it.
fn close_commit(buf: &mut Vec<u8>, ptag: &mut u32, from: usize) {
    // A four-byte "padding" is exactly the checksum that follows.
    let ccrc = tag::Tag::new(tag::TYPE_CCRC, tag::ID_NONE, 4);
    let stored = (ccrc.0 & 0x7fff_ffff) ^ *ptag;
    buf.extend_from_slice(&stored.to_be_bytes());
    let crc = tag::crc(tag::PTAG_INIT, &buf[from..]);
    buf.extend_from_slice(&crc.to_le_bytes());
    *ptag = ccrc.0 & 0x7fff_ffff;
}

/// A metadata block with two commits: the first creates a directory at id 0,
/// the second splices a file in front of it, which shifts the directory to
/// id 1 without rewriting any of its tags.
fn two_commit_block(bs: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes()); // revision count
    let mut ptag = tag::PTAG_INIT;

    push_tag(
        &mut buf,
        &mut ptag,
        tag::Tag::new(tag::TYPE_NAME | tag::TYPE_DIR, 0, 5),
        b"inner",
    );
    let mut pair = [0u8; 8];
    pair[0..4].copy_from_slice(&4u32.to_le_bytes());
    pair[4..8].copy_from_slice(&5u32.to_le_bytes());
    push_tag(
        &mut buf,
        &mut ptag,
        tag::Tag::new(tag::TYPE_DIRSTRUCT, 0, 8),
        &pair,
    );
    close_commit(&mut buf, &mut ptag, 0);

    let second = buf.len();
    push_tag(
        &mut buf,
        &mut ptag,
        tag::Tag::new(tag::TYPE_CREATE, 0, 0),
        &[],
    );
    push_tag(
        &mut buf,
        &mut ptag,
        tag::Tag::new(tag::TYPE_NAME | tag::TYPE_REG, 0, 4),
        b"blob",
    );
    push_tag(
        &mut buf,
        &mut ptag,
        tag::Tag::new(tag::TYPE_INLINESTRUCT, 0, 5),
        b"hello",
    );
    close_commit(&mut buf, &mut ptag, second);

    let mut block = vec![0xffu8; bs];
    block[..buf.len()].copy_from_slice(&buf);
    block
}

#[test]
fn an_id_that_a_later_commit_shifted_keeps_its_name_and_type() {
    let block = two_commit_block(512);
    let m = mdir::parse(&block, [0, 1]).expect("both commits are valid");
    assert_eq!(m.count, 2, "a create raises the pair's id count");

    // The spliced-in file took id 0.
    let (kind, off, len) = mdir::name_of(&block, &m, 0).expect("id 0 has a name");
    assert_eq!(kind, tag::TYPE_REG as u8);
    assert_eq!(&block[off as usize..(off + len) as usize], b"blob");
    assert!(matches!(
        mdir::struct_of(&block, &m, 0),
        Some(Struct::Inline { len: 5, .. })
    ));

    // …and the directory the first commit wrote is now id 1, with the type
    // its untouched name tag still carries. Adjusting the tag's id field by
    // arithmetic instead of replacement used to borrow into the type here,
    // turning the directory into a zero-length file.
    let (kind, off, len) = mdir::name_of(&block, &m, 1).expect("id 1 has a name");
    assert_eq!(kind, tag::TYPE_DIR as u8, "the shifted id lost its type");
    assert_eq!(&block[off as usize..(off + len) as usize], b"inner");
    assert_eq!(mdir::struct_of(&block, &m, 1), Some(Struct::Dir([4, 5])));

    // Nothing was ever written for id 2.
    assert!(mdir::name_of(&block, &m, 2).is_none());
}

#[test]
fn a_later_commit_overrides_an_earlier_tag_for_the_same_id() {
    // The newest tag for a (type, id) wins, which is what makes a metadata
    // block an append-only log of overrides.
    let bs = 512;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&7u32.to_le_bytes());
    let mut ptag = tag::PTAG_INIT;
    push_tag(
        &mut buf,
        &mut ptag,
        tag::Tag::new(tag::TYPE_NAME | tag::TYPE_REG, 0, 3),
        b"log",
    );
    push_tag(
        &mut buf,
        &mut ptag,
        tag::Tag::new(tag::TYPE_INLINESTRUCT, 0, 3),
        b"old",
    );
    close_commit(&mut buf, &mut ptag, 0);
    let second = buf.len();
    push_tag(
        &mut buf,
        &mut ptag,
        tag::Tag::new(tag::TYPE_INLINESTRUCT, 0, 6),
        b"newest",
    );
    close_commit(&mut buf, &mut ptag, second);
    let mut block = vec![0xffu8; bs];
    block[..buf.len()].copy_from_slice(&buf);

    let m = mdir::parse(&block, [0, 1]).expect("both commits are valid");
    let Some(Struct::Inline { off, len }) = mdir::struct_of(&block, &m, 0) else {
        panic!("no inline struct for id 0");
    };
    assert_eq!(&block[off as usize..(off + len) as usize], b"newest");
}

#[test]
fn a_half_written_commit_is_ignored() {
    // The tail of the block is a commit whose CRC never landed; everything
    // it said has to be invisible.
    let bs = 512;
    let mut block = two_commit_block(bs);
    let good = mdir::parse(&block, [0, 1]).expect("baseline");
    // Append a tag run with no CRC tag at all, the way a power cut leaves it.
    let mut ptag = good.etag;
    let mut torn: Vec<u8> = Vec::new();
    push_tag(
        &mut torn,
        &mut ptag,
        tag::Tag::new(tag::TYPE_NAME | tag::TYPE_REG, 2, 5),
        b"ghost",
    );
    let at = good.off as usize;
    block[at..at + torn.len()].copy_from_slice(&torn);

    let m = mdir::parse(&block, [0, 1]).expect("the good commits still parse");
    assert_eq!(m.count, good.count, "a torn commit changed the id count");
    assert_eq!(m.off, good.off);
    assert!(mdir::name_of(&block, &m, 2).is_none(), "the ghost was read");
}

#[test]
fn entries_stay_in_order_as_a_directory_splits_again_and_again() {
    // Each of these commits overflows the pair it lands in, so the chain
    // grows one fresh pair at a time — and the last insert sorts before
    // everything already there, which pushes every id along. An allocator
    // that lost sight of a pair claimed mid-commit, or a chain walked in
    // the wrong order, shows up here as a missing or swapped entry.
    let mut vol = fresh_small(64);
    // 512-byte blocks: ~200 bytes of entries fill a pair's split limit, so
    // a handful of 40-byte inline files overflow it several times over.
    let mut expect: Vec<(alloc::string::String, Vec<u8>)> = Vec::new();
    for i in 0..30u32 {
        let name = alloc::format!("/f{i:02}");
        let body = vec![b'a' + (i % 26) as u8; 40];
        write_file(&mut vol, &name, &body);
        expect.push((name, body));
    }
    // And an entry that sorts first, so the insert lands at id 0 of the
    // first pair and pushes everything along.
    write_file(&mut vol, "/AAA", b"sorts first");
    expect.push((alloc::string::String::from("/AAA"), b"sorts first".to_vec()));

    let mut vol = remount(vol);
    for (name, body) in &expect {
        assert_eq!(&read_all(&mut vol, name), body, "{name}");
    }
    let names = list(&mut vol, "/");
    assert_eq!(names.len(), expect.len());
    let mut sorted: Vec<Vec<u8>> = expect
        .iter()
        .map(|(n, _)| n.as_bytes()[1..].to_vec())
        .collect();
    sorted.sort();
    assert_eq!(names, sorted, "the chain is out of name order");
}

#[test]
fn a_file_written_across_a_lookahead_refill_is_not_cross_linked() {
    // Three files, each larger than the lookahead window is wide, written
    // one after another on a volume where the window has to be refilled
    // repeatedly. Any block handed out twice shows up as a file reading
    // back as another one's bytes.
    let mut vol = fresh_small(400);
    let bodies: Vec<Vec<u8>> = (0..3u32).map(|i| vec![0x10u8 + i as u8; 50_000]).collect();
    for (i, body) in bodies.iter().enumerate() {
        write_file(&mut vol, &alloc::format!("/big{i}.bin"), body);
    }
    let mut vol = remount(vol);
    for (i, body) in bodies.iter().enumerate() {
        assert_eq!(
            &read_all(&mut vol, &alloc::format!("/big{i}.bin")),
            body,
            "file {i}"
        );
    }
}

#[test]
fn the_split_point_halves_until_the_tail_fits() {
    // The pure arithmetic behind a split, which decides how many entries
    // stay behind. A commit loops on it, so a head that still does not fit
    // is peeled again rather than written too large.
    let mut sizes = [0u16; MAX_IDS + 1];

    // Everything fits: nothing is peeled off (the caller does not even ask).
    sizes[..4].copy_from_slice(&[50, 50, 50, 50]);
    assert_eq!(split_point(&sizes, 4, 256), 0);

    // One entry too many: the tail that is peeled has to fit the limit…
    sizes[..5].copy_from_slice(&[70, 70, 70, 70, 70]);
    let at = split_point(&sizes, 5, 256);
    assert!(at > 0, "nothing was peeled off");
    let tail: usize = sizes[at as usize..5].iter().map(|n| *n as usize).sum();
    assert!(tail <= 256, "the peeled tail is {tail} bytes");

    // …and when the head still does not, the caller's loop peels again,
    // which this checks by running the same step on the head.
    sizes[..4].copy_from_slice(&[150, 150, 150, 150]);
    let at = split_point(&sizes, 4, 256);
    let head: usize = sizes[..at as usize].iter().map(|n| *n as usize).sum();
    if head > 256 {
        let again = split_point(&sizes, at, 256);
        assert!(again < at, "the second peel made no progress");
        let tail: usize = sizes[again as usize..at as usize]
            .iter()
            .map(|n| *n as usize)
            .sum();
        assert!(tail <= 256, "the second tail is {tail} bytes");
    }

    // A single entry no block can hold is reported as such (0 = give up).
    sizes[0] = 500;
    assert_eq!(split_point(&sizes, 1, 256), 0);
}

#[test]
fn reformatting_a_volume_that_had_data_starts_from_nothing() {
    let mut vol = fresh();
    write_file(&mut vol, "/old.bin", &vec![5u8; 30_000]);
    vol.create_dir("/olddir").unwrap();
    let flash = vol.unmount().unwrap();

    let mut vol = Volume::<_, 4096, 256>::format(flash).unwrap();
    assert!(list(&mut vol, "/").is_empty(), "the old tree survived");
    assert_eq!(
        vol.used_blocks().unwrap(),
        2,
        "the old data is still counted as live"
    );
    // The space the old tree held is handed out again.
    write_file(&mut vol, "/new.bin", &vec![6u8; 200_000]);
    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/new.bin"), vec![6u8; 200_000]);
    assert!(!vol.exists("/old.bin").unwrap());
}

#[test]
fn two_handles_appending_in_turn_stay_separate() {
    // Each write is a real commit, so the two files' skip-lists and their
    // entries are rewritten alternately — a handle that followed the wrong
    // entry, or a block handed to both, shows up as mixed-up contents.
    let mut vol = fresh();
    let mut a = vol.create_file("/a.log").unwrap();
    let mut b = vol.create_file("/b.log").unwrap();
    let mut want_a = Vec::new();
    let mut want_b = Vec::new();
    for i in 0..25u32 {
        let la = alloc::format!("a{i:03}: {}\n", "x".repeat(200));
        let lb = alloc::format!("b{i:03}: {}\n", "y".repeat(300));
        a.seek_to_end(&mut vol);
        a.write_all(&mut vol, la.as_bytes()).unwrap();
        b.seek_to_end(&mut vol);
        b.write_all(&mut vol, lb.as_bytes()).unwrap();
        want_a.extend_from_slice(la.as_bytes());
        want_b.extend_from_slice(lb.as_bytes());
    }
    assert_eq!(a.len() as usize, want_a.len());
    assert_eq!(b.len() as usize, want_b.len());

    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/a.log"), want_a);
    assert_eq!(read_all(&mut vol, "/b.log"), want_b);
}

#[test]
fn a_handle_reads_what_it_just_wrote_without_a_remount() {
    // The handle's own cursor and the entry it points at have to stay in
    // step across the commit each write performs.
    let mut vol = fresh();
    let mut f = vol.create_file("/rw.bin").unwrap();
    f.write_all(&mut vol, b"first").unwrap();
    f.seek(0);
    let mut buf = [0u8; 5];
    f.read_exact(&mut vol, &mut buf).unwrap();
    assert_eq!(&buf, b"first");

    // Grow it past the inline limit and read back through the same handle.
    let body = vec![0x77u8; 20_000];
    f.seek_to_end(&mut vol);
    f.write_all(&mut vol, &body).unwrap();
    assert_eq!(f.len(), 5 + body.len() as u32);
    f.seek(5);
    let mut out = vec![0u8; body.len()];
    f.read_exact(&mut vol, &mut out).unwrap();
    assert_eq!(out, body);
}

#[test]
fn a_program_page_as_large_as_a_block_still_commits() {
    // The edge of the padding rules: a commit padded to the program size
    // fills the whole block, so there is no room left for a forward CRC and
    // none is written. littlefs reads such a block by compacting it rather
    // than appending, which costs nothing here — every commit is a
    // compaction anyway.
    let flash = RamFlash::new(32, 512).with_prog_size(512);
    let mut vol = Volume::<_, 512, 512>::format(flash).unwrap();
    write_file(&mut vol, "/a", b"one page per commit");
    vol.create_dir("/d").unwrap();
    write_file(&mut vol, "/d/b", &vec![2u8; 3_000]);
    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/a"), b"one page per commit");
    assert_eq!(read_all(&mut vol, "/d/b"), vec![2u8; 3_000]);
    assert_eq!(list(&mut vol, "/"), [b"a".to_vec(), b"d".to_vec()]);
}
