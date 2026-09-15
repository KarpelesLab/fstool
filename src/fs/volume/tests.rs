//! Tests for the generic layer: every driver through the traits, and
//! [`mount`](super::mount) finding each one wherever a card keeps it.
//!
//! They run in every configuration that compiles the layer, the heapless
//! ones included, so volumes are laid out by the drivers' own test
//! formatters (FAT, exFAT) or the driver itself (littlefs). What the drivers
//! write is checked against the reference tools in `tests/`; what is checked
//! here is that the traits say the same thing the drivers do.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;

use super::*;
use crate::device::SectorDriver;

/// A RAM card that holds its user to the [`SectorDriver`] contract.
#[derive(Debug)]
struct Card(Vec<u8>);

impl Card {
    fn blank(sectors: usize) -> Self {
        Card(vec![0u8; sectors * 512])
    }
}

impl SectorDriver for Card {
    type Error = core::convert::Infallible;

    fn sector_size(&self) -> u32 {
        512
    }

    fn sector_count(&self) -> u64 {
        self.0.len() as u64 / 512
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        assert!(
            !buf.is_empty() && buf.len().is_multiple_of(512),
            "partial sector"
        );
        let at = lba as usize * 512;
        assert!(at + buf.len() <= self.0.len(), "read past the card");
        buf.copy_from_slice(&self.0[at..at + buf.len()]);
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
        assert!(
            !buf.is_empty() && buf.len().is_multiple_of(512),
            "partial sector"
        );
        let at = lba as usize * 512;
        assert!(at + buf.len() <= self.0.len(), "write past the card");
        self.0[at..at + buf.len()].copy_from_slice(buf);
        Ok(())
    }
}

/// Sectors every fixture volume spans: 16 MiB.
const VOL_SECTORS: u32 = 32 * 1024;

#[cfg(feature = "fat")]
fn lay_out_fat(card: &mut Card, start: u32) {
    use crate::fs::fat::FatKind;
    crate::fs::fat::volume_tests::format(
        &mut card.0,
        start as usize,
        VOL_SECTORS,
        2,
        FatKind::Fat16,
    );
}

#[cfg(feature = "exfat")]
fn lay_out_exfat(card: &mut Card, start: u32) {
    use crate::fs::exfat::volume_tests::{RamCard, format};
    let mut ram = RamCard::new(1);
    ram.data = core::mem::take(&mut card.0);
    format(&mut ram, start, VOL_SECTORS, 8);
    card.0 = ram.data;
}

#[cfg(feature = "littlefs")]
fn lay_out_littlefs(card: &mut Card, start: u32, block_size: u32) {
    use crate::device::SectorFlash;
    use crate::fs::littlefs;
    let taken = Card(core::mem::take(&mut card.0));
    let flash = SectorFlash::<_, 512>::new(taken, start as u64, VOL_SECTORS as u64, block_size)
        .expect("adapter");
    let vol = littlefs::Volume::<_, 4096, 512>::format(flash).expect("format");
    card.0 = vol.unmount().expect("unmount").into_inner().0;
}

/// Read a whole file through the traits.
fn read_all<V: Volume>(vol: &mut V, path: &str) -> Vec<u8>
where
    V::Error: Debug,
{
    let mut f = vol.open_file(path).unwrap();
    let mut out = vec![0u8; f.len() as usize];
    f.read_exact(vol, &mut out).unwrap();
    out
}

/// A directory's names, through the traits.
fn names<V: Volume>(vol: &mut V, path: &str) -> Vec<String>
where
    V::Error: Debug,
{
    let dir = vol.open_dir(path).unwrap();
    let mut it = vol.iter_dir(dir);
    let mut out = Vec::new();
    while let Some(e) = it.next().unwrap() {
        out.push(String::from(e.name_str().expect("UTF-8 name")));
    }
    out.sort();
    out
}

/// What every filesystem has to get right through the generic interface,
/// written once. It leaves `/keep/data.bin` behind for a remount to check.
fn workout<V: Volume>(vol: &mut V)
where
    V::Error: Debug,
{
    let total = vol.total_bytes();
    let free = vol.free_bytes().unwrap();
    assert!(total > 0 && free <= total, "{free} free of {total}");
    // statfs says the same thing in allocation units.
    let st = vol.statfs().unwrap();
    assert!(
        st.block_size.is_power_of_two() && st.block_size >= 512,
        "{st:?}"
    );
    assert_eq!((st.total_bytes(), st.free_bytes()), (total, free), "{st:?}");
    assert_eq!(st.blocks_avail, st.blocks_free);
    assert_eq!((st.inodes, st.inodes_free), (0, 0));
    assert_eq!(st.name_max, 255);

    vol.create_dir("/logs").unwrap();
    let mut f = vol.create_file("/logs/boot.txt").unwrap();
    f.write_all(vol, b"hello ").unwrap();
    f.flush(vol).unwrap();

    // Reopen, append.
    let mut f = vol.open_file("/logs/boot.txt").unwrap();
    assert_eq!((f.len(), f.pos()), (6, 0));
    f.seek_to_end(vol).unwrap();
    f.write_all(vol, b"world").unwrap();
    f.flush(vol).unwrap();
    assert_eq!(read_all(vol, "/logs/boot.txt"), b"hello world");

    // Seek into the middle and read to the end.
    let mut f = vol.open_file("/logs/boot.txt").unwrap();
    f.seek(vol, 6).unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(f.read(vol, &mut buf).unwrap(), 5);
    assert_eq!(&buf[..5], b"world");
    assert_eq!(f.read(vol, &mut buf).unwrap(), 0);

    // Truncate, then extend: the extension reads as zeros.
    let mut f = vol.open_file("/logs/boot.txt").unwrap();
    f.set_len(vol, 5).unwrap();
    f.flush(vol).unwrap();
    assert_eq!(read_all(vol, "/logs/boot.txt"), b"hello");
    let mut f = vol.open_file("/logs/boot.txt").unwrap();
    f.set_len(vol, 8).unwrap();
    f.flush(vol).unwrap();
    assert_eq!(read_all(vol, "/logs/boot.txt"), b"hello\0\0\0");

    let m = vol.metadata("/logs/boot.txt").unwrap();
    assert!(m.is_file() && !m.is_dir());
    assert_eq!(m.len(), 8);
    assert_eq!(vol.metadata("/logs").unwrap().kind(), Kind::Dir);
    assert!(vol.exists("/logs/boot.txt").unwrap());
    assert!(!vol.exists("/logs/nope.txt").unwrap());

    // Errors come out as the same kinds whichever driver made them.
    assert_eq!(
        vol.open_file("/nope.txt").unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert!(vol.metadata("/nope/deeper").unwrap_err().is_not_found());
    assert_eq!(
        vol.create_dir("/logs").unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        vol.remove_dir("/logs").unwrap_err().kind(),
        ErrorKind::DirectoryNotEmpty
    );
    assert_eq!(
        vol.open_file("/logs").unwrap_err().kind(),
        ErrorKind::IsADirectory
    );

    // Listings: no `.` or `..`, whatever the filesystem stores.
    assert_eq!(names(vol, "/logs"), ["boot.txt"]);
    assert!(names(vol, "/").contains(&String::from("logs")));

    vol.remove_file("/logs/boot.txt").unwrap();
    assert!(names(vol, "/logs").is_empty());
    vol.remove_dir("/logs").unwrap();
    assert!(!names(vol, "/").contains(&String::from("logs")));

    // Something bigger than a cluster or a block, left for the remount.
    let body: Vec<u8> = (0..20_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let dir = vol.create_dir("/keep").unwrap();
    let mut f = vol.open_or_create_file("/keep/data.bin").unwrap();
    f.write_all(vol, &body).unwrap();
    f.flush(vol).unwrap();
    assert_eq!(read_all(vol, "/keep/data.bin"), body);
    let mut it = vol.iter_dir(dir);
    let e = it.next().unwrap().expect("one entry");
    assert_eq!(
        (e.name(), e.len(), e.is_dir()),
        (&b"data.bin"[..], 20_000, false)
    );
    drop(it);
    vol.flush().unwrap();
    assert!(vol.free_bytes().unwrap() < free);
    // The data just written is gone from statfs's free count too, by at
    // least the allocation units it needed.
    let after = vol.statfs().unwrap();
    assert_eq!(after.blocks, st.blocks);
    let needed = 20_000u64.div_ceil(st.block_size as u64);
    assert!(
        st.blocks_free - after.blocks_free >= needed,
        "{st:?} -> {after:?}"
    );
    assert_eq!(after.free_bytes(), vol.free_bytes().unwrap());
}

fn kept() -> Vec<u8> {
    (0..20_000u32).map(|i| (i * 7 % 251) as u8).collect()
}

#[cfg(feature = "fat")]
#[test]
fn the_fat_driver_passes_the_workout_through_the_traits() {
    let mut card = Card::blank(VOL_SECTORS as usize);
    lay_out_fat(&mut card, 0);
    let mut vol = crate::fs::fat::Volume::<_, 512>::mount(card).unwrap();
    assert_eq!(vol.fs_type(), FsType::Fat);
    workout(&mut vol);
    let card = Volume::unmount(vol).unwrap();
    let mut vol = crate::fs::fat::Volume::<_, 512>::mount(card).unwrap();
    assert_eq!(read_all(&mut vol, "/keep/data.bin"), kept());
}

#[cfg(feature = "exfat")]
#[test]
fn the_exfat_driver_passes_the_workout_through_the_traits() {
    let mut card = Card::blank(VOL_SECTORS as usize);
    lay_out_exfat(&mut card, 0);
    let mut vol = crate::fs::exfat::Volume::<_, 512>::mount(card).unwrap();
    assert_eq!(vol.fs_type(), FsType::Exfat);
    workout(&mut vol);
    let card = Volume::unmount(vol).unwrap();
    let mut vol = crate::fs::exfat::Volume::<_, 512>::mount(card).unwrap();
    assert_eq!(read_all(&mut vol, "/keep/data.bin"), kept());
}

#[cfg(feature = "littlefs")]
#[test]
fn the_littlefs_driver_passes_the_workout_through_the_traits() {
    use crate::device::SectorFlash;
    let mut card = Card::blank(VOL_SECTORS as usize);
    lay_out_littlefs(&mut card, 0, 1024);
    let flash = SectorFlash::<_, 512>::whole(card, 1024).unwrap();
    let mut vol = crate::fs::littlefs::Volume::<_, 4096, 512>::mount(flash).unwrap();
    assert_eq!(vol.fs_type(), FsType::LittleFs);
    workout(&mut vol);
    let flash = Volume::unmount(vol).unwrap();
    let mut vol = crate::fs::littlefs::Volume::<_, 4096, 512>::mount(flash).unwrap();
    assert_eq!(read_all(&mut vol, "/keep/data.bin"), kept());
}

/// Every filesystem compiled in, laid out on a whole card.
fn whole_cards() -> Vec<(FsType, Card)> {
    let mut out = Vec::new();
    #[cfg(feature = "fat")]
    {
        let mut c = Card::blank(VOL_SECTORS as usize);
        lay_out_fat(&mut c, 0);
        out.push((FsType::Fat, c));
    }
    #[cfg(feature = "exfat")]
    {
        let mut c = Card::blank(VOL_SECTORS as usize);
        lay_out_exfat(&mut c, 0);
        out.push((FsType::Exfat, c));
    }
    #[cfg(feature = "littlefs")]
    for bs in [512, 4096] {
        let mut c = Card::blank(VOL_SECTORS as usize);
        lay_out_littlefs(&mut c, 0, bs);
        out.push((FsType::LittleFs, c));
    }
    out
}

#[test]
fn mount_recognises_each_filesystem_and_the_workout_passes_through_it() {
    for (fs, card) in whole_cards() {
        let mut vol = mount::<_, 512, 4096>(card).unwrap_or_else(|e| panic!("{fs:?}: {e:?}"));
        assert_eq!(vol.fs_type(), fs);
        workout(&mut vol);
        let card = vol.unmount().unwrap();
        let mut vol = mount::<_, 512, 4096>(card).unwrap();
        assert_eq!(vol.fs_type(), fs);
        assert_eq!(read_all(&mut vol, "/keep/data.bin"), kept(), "{fs:?}");
    }
}

#[test]
fn a_blank_card_holds_nothing_and_says_so() {
    let mut card = Card::blank(4096);
    assert_eq!(probe::<_, 512>(&mut card).unwrap(), None);
    let err = mount::<_, 512, 4096>(card).unwrap_err();
    assert_eq!(err, AnyError::NotRecognised);
    assert_eq!(err.kind(), ErrorKind::NotRecognised);
}

#[test]
fn a_scratch_smaller_than_a_sector_is_refused() {
    let mut card = Card::blank(64);
    assert!(matches!(
        probe::<_, 256>(&mut card),
        Err(AnyError::ScratchTooSmall {
            needed: 512,
            got: 256
        })
    ));
}

/// Write an MBR whose slots are `(type, start, sectors)`.
fn write_mbr(card: &mut Card, slots: &[(u8, u32, u32)]) {
    card.0[..512].fill(0);
    for (i, &(kind, start, sectors)) in slots.iter().enumerate() {
        let at = 446 + i * 16;
        card.0[at + 4] = kind;
        card.0[at + 8..at + 12].copy_from_slice(&start.to_le_bytes());
        card.0[at + 12..at + 16].copy_from_slice(&sectors.to_le_bytes());
    }
    card.0[510] = 0x55;
    card.0[511] = 0xAA;
}

/// Write a GPT describing `parts` as `(start, sectors)`: protective MBR,
/// primary header and array, and the backup pair at the end.
fn write_gpt(card: &mut Card, parts: &[(u32, u32)]) {
    use crate::device::gpt;
    let total = card.0.len() as u64 / 512;
    write_mbr(card, &[(0xEE, 1, (total - 1) as u32)]);

    let mut array = vec![0u8; 128 * 128];
    for (i, &(start, sectors)) in parts.iter().enumerate() {
        let e = &mut array[i * 128..(i + 1) * 128];
        e[0..16].copy_from_slice(&gpt::LINUX_FS.0);
        e[16..32].copy_from_slice(&[i as u8 + 1; 16]);
        e[32..40].copy_from_slice(&(start as u64).to_le_bytes());
        e[40..48].copy_from_slice(&(start as u64 + sectors as u64 - 1).to_le_bytes());
    }
    let array_crc = crate::crc::crc32(&array);
    let backup_array = total - 1 - 32;
    card.0[2 * 512..][..array.len()].copy_from_slice(&array);
    card.0[backup_array as usize * 512..][..array.len()].copy_from_slice(&array);

    let header = |my: u64, alt: u64, entries: u64| {
        let mut h = [0u8; 512];
        h[0..8].copy_from_slice(gpt::SIGNATURE);
        h[8..12].copy_from_slice(&gpt::REVISION.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&my.to_le_bytes());
        h[32..40].copy_from_slice(&alt.to_le_bytes());
        h[40..48].copy_from_slice(&34u64.to_le_bytes());
        h[48..56].copy_from_slice(&(total - 34).to_le_bytes());
        h[72..80].copy_from_slice(&entries.to_le_bytes());
        h[80..84].copy_from_slice(&128u32.to_le_bytes());
        h[84..88].copy_from_slice(&128u32.to_le_bytes());
        h[88..92].copy_from_slice(&array_crc.to_le_bytes());
        let crc = crate::crc::crc32(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    };
    card.0[512..1024].copy_from_slice(&header(1, total - 1, 2));
    card.0[(total - 1) as usize * 512..].copy_from_slice(&header(total - 1, 1, backup_array));
}

/// Lay out `fs` at `start`.
fn lay_out(card: &mut Card, fs: FsType, start: u32) {
    match fs {
        #[cfg(feature = "fat")]
        FsType::Fat => lay_out_fat(card, start),
        #[cfg(feature = "exfat")]
        FsType::Exfat => lay_out_exfat(card, start),
        #[cfg(feature = "littlefs")]
        FsType::LittleFs => lay_out_littlefs(card, start, 2048),
        #[allow(unreachable_patterns)]
        _ => unreachable!("{fs:?} is not compiled in"),
    }
}

fn compiled() -> Vec<FsType> {
    whole_cards().into_iter().map(|(fs, _)| fs).collect()
}

#[test]
fn the_first_recognised_mbr_partition_is_the_one_mounted() {
    const FIRST: u32 = 2048;
    let second = FIRST + VOL_SECTORS;
    for fs in compiled() {
        // Slot 1 is a partition holding nothing; slot 2 holds the volume.
        let mut card = Card::blank((second + VOL_SECTORS) as usize);
        lay_out(&mut card, fs, second);
        write_mbr(
            &mut card,
            &[(0x83, FIRST, VOL_SECTORS), (0x0C, second, VOL_SECTORS)],
        );

        let found = probe::<_, 512>(&mut card).unwrap().expect("found");
        assert_eq!(
            (found.fs, found.start_lba, found.sectors),
            (fs, second as u64, VOL_SECTORS as u64)
        );

        let mut vol = mount_found::<_, 512, 4096>(card, found).unwrap();
        let mut f = vol.create_file("/in-slot-2.txt").unwrap();
        f.write_all(&mut vol, b"second slot").unwrap();
        f.flush(&mut vol).unwrap();
        let card = vol.unmount().unwrap();
        // Nothing before the partition was written.
        assert!(
            card.0[512..second as usize * 512].iter().all(|&b| b == 0),
            "{fs:?}"
        );
        let mut vol = mount::<_, 512, 4096>(card).unwrap();
        assert_eq!(read_all(&mut vol, "/in-slot-2.txt"), b"second slot");
    }
}

#[test]
fn a_gpt_partition_is_found_through_the_table() {
    const FIRST: u32 = 2048;
    let second = FIRST + 4096;
    for fs in compiled() {
        let mut card = Card::blank((second + VOL_SECTORS + 64) as usize);
        lay_out(&mut card, fs, second);
        write_gpt(&mut card, &[(FIRST, 4096), (second, VOL_SECTORS)]);
        let found = probe::<_, 512>(&mut card).unwrap().expect("found");
        assert_eq!((found.fs, found.start_lba), (fs, second as u64), "{fs:?}");
        let mut vol = mount::<_, 512, 4096>(card).unwrap();
        assert!(names(&mut vol, "/").is_empty(), "{fs:?}");
    }
}

#[cfg(feature = "littlefs")]
#[test]
fn a_littlefs_block_larger_than_the_scratch_is_refused_before_mounting() {
    let mut card = Card::blank(VOL_SECTORS as usize);
    lay_out_littlefs(&mut card, 0, 4096);
    let found = probe::<_, 512>(&mut card).unwrap().expect("found");
    assert_eq!((found.fs, found.block_size), (FsType::LittleFs, 4096));
    assert!(matches!(
        mount_found::<_, 512, 2048>(card, found),
        Err(AnyError::BlockSize(4096))
    ));
}

#[cfg(all(feature = "fat", feature = "littlefs"))]
#[test]
fn a_handle_from_another_volume_is_refused() {
    let mut a = Card::blank(VOL_SECTORS as usize);
    lay_out_fat(&mut a, 0);
    let mut b = Card::blank(VOL_SECTORS as usize);
    lay_out_littlefs(&mut b, 0, 1024);
    let mut fat = mount::<_, 512, 4096>(a).unwrap();
    let mut lfs = mount::<_, 512, 4096>(b).unwrap();

    let mut file = fat.create_file("/a.txt").unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(
        file.read(&mut lfs, &mut buf).unwrap_err(),
        AnyError::WrongVolume
    );
    let dir = fat.root();
    let mut it = lfs.iter_dir(dir);
    assert_eq!(it.next().unwrap_err().kind(), ErrorKind::WrongVolume);
}

#[cfg(feature = "fat")]
#[test]
fn a_fat_offset_past_4_gib_is_an_error_not_a_wrap() {
    let mut card = Card::blank(VOL_SECTORS as usize);
    lay_out_fat(&mut card, 0);
    let mut vol = crate::fs::fat::Volume::<_, 512>::mount(card).unwrap();
    let mut f = Volume::create_file(&mut vol, "/big").unwrap();
    assert_eq!(
        VolumeFile::seek(&mut f, &mut vol, 1 << 32)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidOffset
    );
    assert_eq!(
        VolumeFile::set_len(&mut f, &mut vol, 1 << 32)
            .unwrap_err()
            .kind(),
        ErrorKind::FileTooLarge
    );
}

/// Every filesystem compiled in, as [`format`] is told to lay it down.
#[allow(clippy::vec_init_then_push)] // each push is behind its own feature
fn format_requests() -> Vec<(FsType, FormatAs<'static>)> {
    let mut out = Vec::new();
    #[cfg(feature = "fat")]
    out.push((
        FsType::Fat,
        FormatAs::Fat(crate::fs::fat::FormatOpts::default()),
    ));
    #[cfg(feature = "exfat")]
    out.push((
        FsType::Exfat,
        FormatAs::Exfat(crate::fs::exfat::VolumeFormatOpts::default()),
    ));
    #[cfg(feature = "littlefs")]
    out.push((
        FsType::LittleFs,
        FormatAs::LittleFs {
            block_size: 4096,
            opts: crate::fs::littlefs::FormatOpts::default(),
        },
    ));
    out
}

#[test]
fn format_lays_each_filesystem_down_and_mount_finds_it_again() {
    const START: u32 = 2048;
    for (fs, how) in format_requests() {
        // A dirty card, partitioned, with the volume in slot 1.
        let mut card = Card(vec![0xA5u8; (START + VOL_SECTORS) as usize * 512]);
        write_mbr(&mut card, &[(0x0C, START, VOL_SECTORS)]);
        let mut vol = format::<_, 512, 4096>(card, START as u64, VOL_SECTORS as u64, how)
            .unwrap_or_else(|e| panic!("{fs:?}: {e:?}"));
        assert_eq!(vol.fs_type(), fs);
        assert!(
            names(&mut vol, "/").is_empty(),
            "{fs:?}: a fresh volume lists nothing"
        );
        workout(&mut vol);
        let card = vol.unmount().unwrap();
        let mut vol = mount::<_, 512, 4096>(card).unwrap();
        assert_eq!(vol.fs_type(), fs);
        assert_eq!(read_all(&mut vol, "/keep/data.bin"), kept(), "{fs:?}");
    }
}

#[cfg(feature = "littlefs")]
#[test]
fn a_littlefs_block_the_scratch_cannot_hold_is_refused_before_formatting() {
    let card = Card::blank(VOL_SECTORS as usize);
    let how = FormatAs::LittleFs {
        block_size: 8192,
        opts: Default::default(),
    };
    assert!(matches!(
        format::<_, 512, 4096>(card, 0, VOL_SECTORS as u64, how),
        Err(AnyError::BlockSize(8192))
    ));
}

#[cfg(feature = "exfat")]
#[test]
fn an_sd_card_gets_fat_up_to_32_gib_and_exfat_above() {
    let gib = (1u64 << 30) / 512;
    assert!(matches!(FormatAs::sd_card(2 * gib, 512), FormatAs::Fat(_)));
    assert!(matches!(FormatAs::sd_card(32 * gib, 512), FormatAs::Fat(_)));
    assert!(matches!(
        FormatAs::sd_card(32 * gib + 1, 512),
        FormatAs::Exfat(_)
    ));
    assert!(matches!(
        FormatAs::sd_card(64 * gib / 8, 4096),
        FormatAs::Exfat(_)
    ));
}
