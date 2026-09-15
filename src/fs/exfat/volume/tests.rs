//! Tests for the allocator-free exFAT driver.
//!
//! These run in every configuration, including `--no-default-features
//! --features exfat`, the heapless one, so the volumes they work on are laid
//! out by a small formatter right here rather than by
//! [`crate::fs::exfat::Exfat`], which that configuration does not compile.
//! Where the hosted half *is* available, the `cross` module at the end plays
//! the two against each other — and `tests/exfat_external.rs` puts what this
//! driver writes through `fsck.exfat`.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use super::super::layout::{self, ENTRY_SIZE};
use super::*;
use crate::device::gpt;

/// A RAM-backed card that holds the driver to its contract: reads and
/// writes are whole sectors, inside the medium.
#[derive(Debug)]
pub(crate) struct RamCard {
    pub(crate) data: Vec<u8>,
    sector_size: u32,
    reads: u32,
    writes: u32,
}

impl RamCard {
    pub(crate) fn new(sectors: u32) -> Self {
        Self {
            data: vec![0u8; sectors as usize * 512],
            sector_size: 512,
            reads: 0,
            writes: 0,
        }
    }
}

impl SectorDriver for RamCard {
    type Error = core::convert::Infallible;

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn sector_count(&self) -> u64 {
        self.data.len() as u64 / self.sector_size as u64
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        assert!(
            !buf.is_empty() && buf.len().is_multiple_of(self.sector_size as usize),
            "read of {} bytes is not whole sectors",
            buf.len()
        );
        let at = lba as usize * self.sector_size as usize;
        assert!(at + buf.len() <= self.data.len(), "read past the card");
        self.reads += (buf.len() / self.sector_size as usize) as u32;
        buf.copy_from_slice(&self.data[at..at + buf.len()]);
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
        assert!(
            !buf.is_empty() && buf.len().is_multiple_of(self.sector_size as usize),
            "write of {} bytes is not whole sectors",
            buf.len()
        );
        let at = lba as usize * self.sector_size as usize;
        assert!(at + buf.len() <= self.data.len(), "write past the card");
        self.writes += (buf.len() / self.sector_size as usize) as u32;
        self.data[at..at + buf.len()].copy_from_slice(buf);
        Ok(())
    }
}

type Vol = Volume<RamCard, 512>;

/// Sectors of boot region exFAT reserves at the start of a volume: the main
/// region and its backup, twelve sectors each.
const BOOT_REGION: u32 = 24;

/// Lay out a minimal but valid exFAT volume at `offset` sectors into
/// `card`: boot sector, one FAT, an allocation bitmap, an up-case table
/// covering ASCII, and a root directory naming all three.
///
/// This is the driver's own fixture, not a `mkfs`: it writes what a mount
/// reads, and leaves the boot region's backup and checksum sectors alone
/// (the conformance suite formats with the real tools instead).
pub(crate) fn format(card: &mut RamCard, offset: u32, sectors: u32, sectors_per_cluster: u32) {
    const BPS: u32 = 512;
    let spc_shift = sectors_per_cluster.trailing_zeros() as u8;
    let fat_offset = BOOT_REGION;

    // Size the FAT so it maps every cluster the heap can hold, iterating
    // because the FAT's own size changes how many clusters are left.
    let mut fat_length = 1u32;
    let mut cluster_count;
    loop {
        let heap_offset = fat_offset + fat_length;
        cluster_count = (sectors - heap_offset) / sectors_per_cluster;
        let need = ((cluster_count as u64 + 2) * 4).div_ceil(BPS as u64) as u32;
        if need <= fat_length {
            break;
        }
        fat_length = need;
    }
    let heap_offset = fat_offset + fat_length;
    assert!(cluster_count >= 8, "test volume is too small");

    let vol_at = offset as usize * BPS as usize;
    let sec = |s: u32| -> usize { vol_at + s as usize * BPS as usize };

    // -- boot sector ---------------------------------------------------
    {
        let at = sec(0);
        let b = &mut card.data[at..at + 512];
        b.fill(0);
        b[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        b[3..11].copy_from_slice(b"EXFAT   ");
        b[64..72].copy_from_slice(&(offset as u64).to_le_bytes());
        b[72..80].copy_from_slice(&(sectors as u64).to_le_bytes());
        b[80..84].copy_from_slice(&fat_offset.to_le_bytes());
        b[84..88].copy_from_slice(&fat_length.to_le_bytes());
        b[88..92].copy_from_slice(&heap_offset.to_le_bytes());
        b[92..96].copy_from_slice(&cluster_count.to_le_bytes());
        b[96..100].copy_from_slice(&4u32.to_le_bytes()); // root directory
        b[100..104].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        b[104..106].copy_from_slice(&0x0100u16.to_le_bytes()); // revision 1.0
        b[108] = 9; // 512-byte sectors
        b[109] = spc_shift;
        b[110] = 1; // one FAT
        b[111] = 0x80;
        b[510] = 0x55;
        b[511] = 0xAA;
    }

    // -- FAT -----------------------------------------------------------
    // Clusters 2 (bitmap), 3 (up-case) and 4 (root) are one-cluster chains.
    {
        let at = sec(fat_offset);
        let fat = &mut card.data[at..at + fat_length as usize * BPS as usize];
        fat.fill(0);
        fat[0..4].copy_from_slice(&0xFFFF_FFF8u32.to_le_bytes());
        fat[4..8].copy_from_slice(&layout::FAT_EOC.to_le_bytes());
        for c in 2..5usize {
            fat[c * 4..c * 4 + 4].copy_from_slice(&layout::FAT_EOC.to_le_bytes());
        }
    }

    let cluster_at = |c: u32| -> usize {
        vol_at + (heap_offset + (c - 2) * sectors_per_cluster) as usize * BPS as usize
    };
    let cluster_bytes = (sectors_per_cluster * BPS) as usize;

    // -- allocation bitmap (cluster 2) ---------------------------------
    let bitmap_bytes = (cluster_count as u64).div_ceil(8);
    {
        let at = cluster_at(2);
        card.data[at..at + cluster_bytes].fill(0);
        // Clusters 2, 3 and 4 are taken.
        card.data[at] = 0b0000_0111;
    }

    // -- up-case table (cluster 3) -------------------------------------
    // 128 entries, identity except a..z → A..Z: enough for ASCII names,
    // which is what the driver caches at mount.
    let upcase_len = 128u64 * 2;
    {
        let at = cluster_at(3);
        card.data[at..at + cluster_bytes].fill(0);
        for i in 0..128u16 {
            let v = if (b'a' as u16..=b'z' as u16).contains(&i) {
                i - 0x20
            } else {
                i
            };
            let off = at + i as usize * 2;
            card.data[off..off + 2].copy_from_slice(&v.to_le_bytes());
        }
    }
    let upcase_sum = layout::table_checksum(&card.data[cluster_at(3)..cluster_at(3) + 256]);

    // -- root directory (cluster 4) ------------------------------------
    {
        let at = cluster_at(4);
        card.data[at..at + cluster_bytes].fill(0);

        let mut bitmap = [0u8; ENTRY_SIZE];
        bitmap[0] = layout::ENTRY_ALLOCATION_BITMAP;
        bitmap[1] = 0; // first bitmap, FAT-chained
        bitmap[20..24].copy_from_slice(&2u32.to_le_bytes());
        bitmap[24..32].copy_from_slice(&bitmap_bytes.to_le_bytes());
        card.data[at..at + ENTRY_SIZE].copy_from_slice(&bitmap);

        let mut upcase = [0u8; ENTRY_SIZE];
        upcase[0] = layout::ENTRY_UPCASE_TABLE;
        upcase[4..8].copy_from_slice(&upcase_sum.to_le_bytes());
        upcase[20..24].copy_from_slice(&3u32.to_le_bytes());
        upcase[24..32].copy_from_slice(&upcase_len.to_le_bytes());
        card.data[at + ENTRY_SIZE..at + 2 * ENTRY_SIZE].copy_from_slice(&upcase);

        let mut label = [0u8; ENTRY_SIZE];
        label[0] = layout::ENTRY_VOLUME_LABEL;
        label[1] = 4;
        for (i, u) in "TEST".encode_utf16().enumerate() {
            let off = 2 + i * 2;
            label[off..off + 2].copy_from_slice(&u.to_le_bytes());
        }
        card.data[at + 2 * ENTRY_SIZE..at + 3 * ENTRY_SIZE].copy_from_slice(&label);
    }
}

/// A formatted 8 MiB card: 512-byte sectors, 4 KiB clusters.
fn fresh() -> Vol {
    fresh_sized(16 * 1024, 8)
}

fn fresh_sized(sectors: u32, spc: u32) -> Vol {
    let mut card = RamCard::new(sectors);
    format(&mut card, 0, sectors, spc);
    Volume::mount(card).expect("mount")
}

/// Unmount and mount again, so every test checks what a fresh mount sees.
fn remount(vol: Vol) -> Vol {
    let card = vol.unmount().expect("unmount");
    Volume::mount(card).expect("remount")
}

fn list(vol: &mut Vol, path: &str) -> Vec<alloc::string::String> {
    let dir = vol.open_dir(path).expect("open_dir");
    let mut out = Vec::new();
    let mut it = vol.iter_dir(dir);
    while let Some(e) = it.next().expect("iter") {
        out.push(e.name().to_string());
    }
    out
}

fn read_all(vol: &mut Vol, path: &str) -> Vec<u8> {
    let mut f = vol.open_file(path).expect("open_file");
    let mut out = vec![0u8; f.len() as usize];
    f.read_exact(vol, &mut out).expect("read_exact");
    out
}

fn write_file(vol: &mut Vol, path: &str, body: &[u8]) {
    let mut f = vol.open_or_create_file(path).expect("create");
    f.set_len(vol, 0).expect("truncate");
    f.write_all(vol, body).expect("write");
    f.flush(vol).expect("flush");
}

#[test]
fn a_fresh_volume_mounts_and_lists_nothing() {
    let mut vol = fresh();
    assert_eq!(vol.geometry().bytes_per_sector, 512);
    assert_eq!(vol.geometry().sectors_per_cluster, 8);
    assert_eq!(vol.cluster_bytes(), 4096);
    assert_eq!(vol.geometry().revision, (1, 0));
    assert!(vol.is_writable(), "the fixture has an allocation bitmap");
    // The three metadata entries are not files.
    assert!(list(&mut vol, "/").is_empty());
    // Bitmap, up-case table and root directory.
    assert_eq!(vol.used_clusters().unwrap(), 3);
}

#[test]
fn an_unformatted_card_is_refused() {
    let card = RamCard::new(1024);
    assert!(matches!(
        Volume::<_, 512>::mount(card),
        Err(Error::NotExfat)
    ));
}

#[test]
fn a_scratch_buffer_smaller_than_a_sector_is_refused() {
    let mut card = RamCard::new(4096);
    format(&mut card, 0, 4096, 8);
    card.sector_size = 1024;
    assert!(matches!(
        Volume::<_, 512>::mount(card),
        Err(Error::ScratchTooSmall {
            needed: 1024,
            got: 512
        })
    ));
}

#[test]
fn a_volume_whose_sector_size_is_not_the_cards_is_refused() {
    // The fixture says 512-byte sectors; the card claims 1024.
    let mut card = RamCard::new(8192);
    format(&mut card, 0, 8192, 8);
    card.sector_size = 1024;
    assert!(matches!(
        Volume::<_, 1024>::mount(card),
        Err(Error::SectorSizeMismatch {
            volume: 512,
            driver: 1024
        })
    ));
}

#[test]
fn a_file_round_trips_through_a_remount() {
    let mut vol = fresh();
    let body = b"written with no allocator at all";
    write_file(&mut vol, "/hello.txt", body);
    assert_eq!(vol.metadata("/hello.txt").unwrap().len(), body.len() as u64);
    assert!(vol.metadata("/hello.txt").unwrap().is_file());

    let mut vol = remount(vol);
    assert_eq!(list(&mut vol, "/"), ["hello.txt"]);
    assert_eq!(read_all(&mut vol, "/hello.txt"), body);
}

#[test]
fn an_empty_file_owns_no_cluster() {
    let mut vol = fresh();
    let before = vol.used_clusters().unwrap();
    let f = vol.create_file("/empty").unwrap();
    assert_eq!(f.len(), 0);
    assert_eq!(
        vol.used_clusters().unwrap(),
        before,
        "an empty file should not take a cluster"
    );
    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/empty"), Vec::<u8>::new());
    assert_eq!(list(&mut vol, "/"), ["empty"]);
}

#[test]
fn a_file_spanning_many_clusters_reads_back() {
    let mut vol = fresh();
    let body: Vec<u8> = (0..60_000u32).map(|i| (i % 251) as u8).collect();
    write_file(&mut vol, "/big.bin", &body);

    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/big.bin"), body);
    // Awkward-sized reads have to give the same bytes.
    let mut f = vol.open_file("/big.bin").unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 777];
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
fn appending_extends_the_chain() {
    let mut vol = fresh();
    let mut f = vol.create_file("/log.txt").unwrap();
    let mut expect = Vec::new();
    for i in 0..50u32 {
        let line = alloc::format!("line {i} of a log that outgrows its first cluster\n");
        f.seek_to_end();
        f.write_all(&mut vol, line.as_bytes()).unwrap();
        expect.extend_from_slice(line.as_bytes());
        assert_eq!(f.len(), expect.len() as u64);
    }
    f.flush(&mut vol).unwrap();

    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/log.txt"), expect);
}

#[test]
fn writing_in_the_middle_keeps_the_rest() {
    let mut vol = fresh();
    let mut body: Vec<u8> = (0..40_000u32).map(|i| (i % 97) as u8).collect();
    write_file(&mut vol, "/patch.bin", &body);

    let mut f = vol.open_file("/patch.bin").unwrap();
    f.seek(12_345);
    f.write_all(&mut vol, b"PATCHED").unwrap();
    f.flush(&mut vol).unwrap();
    body[12_345..12_352].copy_from_slice(b"PATCHED");

    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/patch.bin"), body);
}

#[test]
fn a_write_past_the_end_zero_fills_the_gap() {
    let mut vol = fresh();
    let mut f = vol.create_file("/sparse.bin").unwrap();
    f.write_all(&mut vol, b"start").unwrap();
    f.seek(20_000);
    f.write_all(&mut vol, b"end").unwrap();
    f.flush(&mut vol).unwrap();
    assert_eq!(f.len(), 20_003);

    let mut vol = remount(vol);
    let got = read_all(&mut vol, "/sparse.bin");
    assert_eq!(&got[..5], b"start");
    assert!(
        got[5..20_000].iter().all(|b| *b == 0),
        "the gap is not zeros"
    );
    assert_eq!(&got[20_000..], b"end");
}

#[test]
fn growing_with_set_len_reads_as_zeros_without_writing_them() {
    // exFAT says the bytes between ValidDataLength and DataLength are zero,
    // so growing a file should touch no data sector at all.
    let mut vol = fresh();
    let mut f = vol.create_file("/grow.bin").unwrap();
    f.write_all(&mut vol, b"abc").unwrap();
    f.flush(&mut vol).unwrap();
    vol.driver_mut().writes = 0;
    f.set_len(&mut vol, 200_000).unwrap();
    let writes = vol.driver().writes;
    assert!(
        writes < 40,
        "{writes} sector writes to grow a file by 200 KB"
    );

    let mut vol = remount(vol);
    let got = read_all(&mut vol, "/grow.bin");
    assert_eq!(got.len(), 200_000);
    assert_eq!(&got[..3], b"abc");
    assert!(got[3..].iter().all(|b| *b == 0));
}

#[test]
fn set_len_truncates_and_gives_the_clusters_back() {
    let mut vol = fresh();
    let body: Vec<u8> = (0..80_000u32).map(|i| (i % 211) as u8).collect();
    write_file(&mut vol, "/shrink.bin", &body);
    let before = vol.used_clusters().unwrap();

    let mut f = vol.open_file("/shrink.bin").unwrap();
    f.set_len(&mut vol, 5_000).unwrap();
    let after = vol.used_clusters().unwrap();
    assert!(
        after < before,
        "truncation kept {after} of {before} clusters"
    );

    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/shrink.bin"), body[..5_000]);

    // And all the way down to nothing.
    let mut f = vol.open_file("/shrink.bin").unwrap();
    f.set_len(&mut vol, 0).unwrap();
    let mut vol = remount(vol);
    assert_eq!(read_all(&mut vol, "/shrink.bin"), Vec::<u8>::new());
    assert_eq!(
        vol.used_clusters().unwrap(),
        3,
        "only metadata should remain"
    );
}

#[test]
fn directories_nest_and_list() {
    let mut vol = fresh();
    vol.create_dir("/etc").unwrap();
    vol.create_dir("/etc/ssl").unwrap();
    write_file(&mut vol, "/etc/ssl/cert.pem", b"----- not a cert -----");
    write_file(&mut vol, "/etc/hostname", b"device-1\n");

    let mut vol = remount(vol);
    assert_eq!(list(&mut vol, "/"), ["etc"]);
    let mut names = list(&mut vol, "/etc");
    names.sort();
    assert_eq!(names, ["hostname", "ssl"]);
    assert_eq!(list(&mut vol, "/etc/ssl"), ["cert.pem"]);
    assert!(vol.metadata("/etc/ssl").unwrap().is_dir());
    assert_eq!(read_all(&mut vol, "/etc/hostname"), b"device-1\n");

    // Path shapes.
    assert!(vol.exists("etc/hostname").unwrap());
    assert!(vol.exists("\\etc\\ssl").unwrap());
    assert!(vol.exists("//etc//ssl/").unwrap());
    assert!(!vol.exists("/etc/nope").unwrap());
    assert!(matches!(vol.metadata("/etc/./x"), Err(Error::InvalidPath)));
    assert!(matches!(
        vol.metadata("/etc/hostname/x"),
        Err(Error::NotADirectory)
    ));
}

#[test]
fn names_are_matched_case_insensitively_through_the_volumes_table() {
    let mut vol = fresh();
    write_file(&mut vol, "/ReadMe.TXT", b"mixed case");
    let mut vol = remount(vol);
    // The listing keeps the case it was created with…
    assert_eq!(list(&mut vol, "/"), ["ReadMe.TXT"]);
    // …and every spelling finds it.
    for spelling in ["/ReadMe.TXT", "/readme.txt", "/README.TXT", "/rEaDmE.tXt"] {
        assert_eq!(read_all(&mut vol, spelling), b"mixed case", "{spelling}");
    }
    // Creating a differently-cased name is a collision.
    assert!(matches!(
        vol.create_file("/README.txt"),
        Err(Error::AlreadyExists)
    ));
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
    for bad in ["/a/b?c", "/a/x*", "/a/pipe|d", "/a/x:y", "/"] {
        assert!(
            matches!(
                vol.create_file(bad),
                Err(Error::InvalidName | Error::InvalidPath)
            ),
            "{bad} was accepted"
        );
    }
    // A trailing separator just names the directory, which is taken.
    assert!(matches!(vol.create_file("/a/"), Err(Error::AlreadyExists)));
}

#[test]
fn removing_files_and_directories() {
    let mut vol = fresh();
    vol.create_dir("/d").unwrap();
    write_file(&mut vol, "/d/big.bin", &vec![7u8; 30_000]);
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
        vol.used_clusters().unwrap(),
        3,
        "removing everything should leave only the volume's own clusters"
    );
}

#[test]
fn a_removed_entrys_slots_are_reused() {
    // exFAT deletes by clearing the in-use bit, so a directory that only
    // ever appended would grow without bound. The run left behind has to
    // come back into use.
    let mut vol = fresh();
    write_file(&mut vol, "/first-file-name.txt", b"one");
    let dir = vol.open_dir("/").unwrap();
    vol.remove_file("/first-file-name.txt").unwrap();
    write_file(&mut vol, "/second-file-nam.txt", b"two");
    // Both names are the same length, so the second set fits exactly where
    // the first one was: the directory should still be one cluster.
    let len = vol.chain_len(&dir.stream).unwrap();
    assert_eq!(len, 1, "the directory grew instead of reusing the slots");

    let mut vol = remount(vol);
    assert_eq!(list(&mut vol, "/"), ["second-file-nam.txt"]);
    assert_eq!(read_all(&mut vol, "/second-file-nam.txt"), b"two");
}

#[test]
fn a_directory_grows_past_its_first_cluster() {
    // 4 KiB clusters hold 128 slots; each of these sets takes three, so
    // fifty entries need a second cluster.
    let mut vol = fresh();
    let mut names = Vec::new();
    for i in 0..50u32 {
        let name = alloc::format!("/entry-{i:03}.dat");
        write_file(&mut vol, &name, alloc::format!("body {i}").as_bytes());
        names.push(name[1..].to_string());
    }
    names.sort();

    let mut vol = remount(vol);
    let mut listed = list(&mut vol, "/");
    listed.sort();
    assert_eq!(listed, names);
    for i in 0..50u32 {
        assert_eq!(
            read_all(&mut vol, &alloc::format!("/entry-{i:03}.dat")),
            alloc::format!("body {i}").as_bytes()
        );
    }
    // The directory's own length has to have been written back, or a
    // stricter reader would stop at the first cluster.
    let dir = vol.open_dir("/").unwrap();
    assert!(vol.chain_len(&dir.stream).unwrap() >= 2);
}

#[test]
fn a_subdirectory_records_its_grown_length() {
    let mut vol = fresh();
    vol.create_dir("/sub").unwrap();
    for i in 0..50u32 {
        write_file(&mut vol, &alloc::format!("/sub/e{i:03}.dat"), b"x");
    }
    let mut vol = remount(vol);
    // DataLength in the parent's entry set must cover both clusters.
    let meta = vol.metadata("/sub").unwrap();
    assert!(
        meta.len() >= 2 * vol.cluster_bytes() as u64,
        "the subdirectory's DataLength is {} bytes",
        meta.len()
    );
    assert_eq!(list(&mut vol, "/sub").len(), 50);
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
    assert_eq!(list(&mut vol, "/"), [name.as_str()]);
    assert_eq!(
        read_all(&mut vol, &alloc::format!("/{name}")),
        b"at the limit"
    );
}

#[test]
fn non_ascii_names_round_trip() {
    let mut vol = fresh();
    for name in ["ünïcode.txt", "日本語.dat", "emoji-🙂.bin"] {
        write_file(&mut vol, &alloc::format!("/{name}"), name.as_bytes());
    }
    let mut vol = remount(vol);
    let mut listed = list(&mut vol, "/");
    listed.sort();
    let mut want = vec!["emoji-🙂.bin", "ünïcode.txt", "日本語.dat"];
    want.sort();
    assert_eq!(listed, want);
    for name in want {
        assert_eq!(
            read_all(&mut vol, &alloc::format!("/{name}")),
            name.as_bytes(),
            "{name}"
        );
    }
}

#[test]
fn running_out_of_space_is_reported() {
    // A card with room for a handful of clusters.
    let mut vol = fresh_sized(1024, 1);
    let mut f = vol.create_file("/hog.bin").unwrap();
    let chunk = vec![3u8; 4096];
    let mut err = None;
    for _ in 0..4096 {
        if let Err(e) = f.write_all(&mut vol, &chunk) {
            err = Some(e);
            break;
        }
    }
    assert!(
        matches!(err, Some(Error::NoSpace)),
        "filling reported {err:?}"
    );
    let _ = f.flush(&mut vol);
    // The volume is still usable afterwards.
    let mut vol = remount(vol);
    assert!(vol.exists("/hog.bin").unwrap());
    assert_eq!(vol.free_clusters().unwrap(), 0);
}

#[test]
fn mounts_a_volume_inside_an_mbr_partition() {
    const START: u32 = 2048;
    let sectors = 16 * 1024;
    let mut card = RamCard::new(START + sectors);
    format(&mut card, START, sectors, 8);
    // A plain MBR with one exFAT-typed partition.
    {
        let mbr = &mut card.data[..512];
        mbr[446 + 4] = 0x07; // IFS / exFAT / NTFS
        mbr[446 + 8..446 + 12].copy_from_slice(&START.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&sectors.to_le_bytes());
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
    }
    // Whole-card mount finds nothing…
    let mut probe = RamCard::new(1);
    probe.data = card.data.clone();
    assert!(matches!(
        Volume::<_, 512>::mount(probe),
        Err(Error::NotExfat)
    ));

    // …but the partition mounts, by number and by probing.
    let mut card2 = RamCard::new(1);
    card2.data = card.data.clone();
    let part = Volume::<_, 512>::partition(&mut card2, 1).unwrap();
    assert_eq!(part.start_lba, START as u64);
    let mut vol = Volume::<_, 512>::mount_partition(card2, 1).unwrap();
    write_file(&mut vol, "/in-partition.txt", b"offset volume");
    let card = vol.unmount().unwrap();

    let mut vol = Volume::<_, 512>::mount_auto(card).unwrap();
    assert_eq!(vol.geometry().part_start, START as u64);
    assert_eq!(read_all(&mut vol, "/in-partition.txt"), b"offset volume");
}

#[test]
fn a_contiguous_file_is_read_and_then_converted_when_it_grows() {
    // `NoFatChain` files are what many cameras write: the clusters are a
    // run and the FAT entries for them are left at zero.
    let mut vol = fresh();
    // Let the driver allocate three clusters, then re-mark the entry as a
    // contiguous run over the same clusters with no FAT chain.
    let body: Vec<u8> = (0..9_000u32).map(|i| (i % 253) as u8).collect();
    write_file(&mut vol, "/run.bin", &body);
    let first = {
        let f = vol.open_file("/run.bin").unwrap();
        assert!(!f.is_contiguous());
        f
    };
    let _ = first;
    {
        let found = vol.find("/run.bin").unwrap().unwrap();
        let parent = found.parent.stream;
        let set = found.set;
        // The three clusters the writer allocated are consecutive on a
        // fresh volume, so the run is the same data.
        vol.update_set(
            &parent,
            &set,
            set.first_cluster,
            set.data_length,
            set.valid_data_length,
            layout::SECFLAG_ALLOC_POSSIBLE | layout::SECFLAG_NO_FAT_CHAIN,
            false,
        )
        .unwrap();
        // Wipe the FAT entries the flag says are meaningless.
        for c in (set.first_cluster..).take(3) {
            vol.set_fat_entry(c, layout::FAT_FREE).unwrap();
        }
        vol.flush().unwrap();
    }

    let mut vol = remount(vol);
    let mut f = vol.open_file("/run.bin").unwrap();
    assert!(f.is_contiguous(), "the flag did not survive");
    let mut out = vec![0u8; body.len()];
    f.read_exact(&mut vol, &mut out).unwrap();
    assert_eq!(out, body, "a contiguous file read wrong");

    // Writing inside the run it already owns leaves it contiguous…
    f.seek(0);
    f.write_all(&mut vol, b"OVERWRITE").unwrap();
    f.flush(&mut vol).unwrap();
    assert!(f.is_contiguous(), "an in-place write should not convert it");

    // …but growing past it has to write the chain the run implies.
    f.seek_to_end();
    f.write_all(&mut vol, &vec![0x5a_u8; 5_000]).unwrap();
    f.flush(&mut vol).unwrap();
    assert!(!f.is_contiguous(), "growing left the NoFatChain flag set");

    let mut vol = remount(vol);
    let got = read_all(&mut vol, "/run.bin");
    assert_eq!(got.len(), body.len() + 5_000);
    assert_eq!(&got[..9], b"OVERWRITE");
    assert_eq!(&got[9..body.len()], &body[9..]);
    assert!(got[body.len()..].iter().all(|b| *b == 0x5a));
}

#[test]
fn a_corrupt_entry_set_checksum_is_refused() {
    let mut vol = fresh();
    write_file(&mut vol, "/f.txt", b"body");
    // Flip a byte of the name entry: the set checksum no longer matches.
    {
        let found = vol.find("/f.txt").unwrap().unwrap();
        let parent = found.parent.stream;
        let pos = found.set.pos + 2 * ENTRY_SIZE as u64;
        let mut slot = vol.read_slot(&parent, pos).unwrap().unwrap();
        slot[2] ^= 0xff;
        vol.write_slot(&parent, pos, &slot).unwrap();
        vol.flush().unwrap();
    }
    let mut vol = remount(vol);
    let dir = vol.open_dir("/").unwrap();
    let mut it = vol.iter_dir(dir);
    assert!(
        matches!(it.next(), Err(Error::CorruptEntry)),
        "a bad checksum was accepted"
    );
}

#[test]
fn a_volume_without_an_allocation_bitmap_is_read_only() {
    let mut vol = fresh();
    write_file(&mut vol, "/keep.txt", b"read me");
    let mut card = vol.unmount().unwrap();
    // Turn the bitmap entry into a deleted slot: the volume is still
    // readable, but nothing may be allocated on it.
    {
        let heap = 24 + 1; // boot region + one FAT sector in this fixture
        let _ = heap;
        // The root directory is cluster 4; its first slot is the bitmap.
        let boot = &card.data[..512];
        let fat_off = layout::le32(boot, 80);
        let fat_len = layout::le32(boot, 84);
        let heap_off = layout::le32(boot, 88);
        let _ = (fat_off, fat_len);
        let spc = 1u32 << boot[109];
        let root_at = (heap_off + (4 - 2) * spc) as usize * 512;
        card.data[root_at] &= !layout::ENTRY_INUSE;
    }
    let mut vol = Volume::<_, 512>::mount(card).unwrap();
    assert!(!vol.is_writable());
    assert_eq!(read_all(&mut vol, "/keep.txt"), b"read me");
    assert!(matches!(
        vol.create_file("/nope.txt"),
        Err(Error::NoAllocationBitmap)
    ));
}

#[test]
fn the_upcase_cache_only_changes_how_much_is_read() {
    let mut vol = fresh();
    write_file(&mut vol, "/Mixed.TXT", b"x");
    assert!(vol.exists("/mixed.txt").unwrap());
    if cfg!(feature = "alloc") {
        // The ASCII prefix answers every lookup here, so the table is only
        // decoded when something outside it is compared.
        let _ = vol.upcase_cache_bytes();
    } else {
        assert_eq!(vol.upcase_cache_bytes(), 0);
    }
}

// ---------------------------------------------------------------------
// Cross-checks against the hosted half, which exists only with `alloc`.
// ---------------------------------------------------------------------

#[cfg(feature = "alloc")]
mod cross {
    use super::*;
    use crate::block::{BlockDevice, MemoryBackend};
    use crate::fs::exfat::Exfat;
    use crate::fs::exfat::format::FormatOpts;
    use crate::io::Cursor;
    use alloc::string::String;

    const BYTES: u64 = 24 * 1024 * 1024;

    /// A volume the hosted half formatted — a real one, with both boot
    /// regions, their checksums, and the standard up-case table.
    fn hosted_format() -> MemoryBackend {
        let mut dev = MemoryBackend::new(BYTES);
        let opts = FormatOpts {
            volume_label: String::from("CROSSCHECK"),
            ..Default::default()
        };
        let mut fs = Exfat::format(&mut dev, &opts).expect("hosted format");
        fs.flush(&mut dev).expect("hosted flush");
        dev
    }

    fn as_card(dev: MemoryBackend) -> RamCard {
        let mut card = RamCard::new(1);
        card.data = dev.into_bytes();
        card
    }

    fn hosted_read(fs: &mut Exfat, dev: &mut MemoryBackend, path: &str) -> Vec<u8> {
        use crate::io::Read;
        let mut out = Vec::new();
        fs.open_file_reader(dev, path)
            .expect("hosted open")
            .read_to_end(&mut out)
            .expect("hosted read");
        out
    }

    #[test]
    fn the_driver_reads_a_volume_the_hosted_half_wrote() {
        let mut dev = hosted_format();
        let mut fs = Exfat::open(&mut dev).unwrap();
        fs.create_dir(&mut dev, "/sub", 0).unwrap();
        let big: Vec<u8> = (0..70_000u32).map(|i| (i % 241) as u8).collect();
        fs.create_file(
            &mut dev,
            "/sub/big.bin",
            &mut Cursor::new(big.clone()),
            big.len() as u64,
            0,
        )
        .unwrap();
        fs.create_file(
            &mut dev,
            "/Mixed Case.txt",
            &mut Cursor::new(b"tiny".to_vec()),
            4,
            0,
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();

        let mut vol = Volume::<_, 512>::mount(as_card(dev)).expect("driver mount");
        let mut names = list(&mut vol, "/");
        names.sort();
        assert_eq!(names, ["Mixed Case.txt", "sub"]);
        assert_eq!(list(&mut vol, "/sub"), ["big.bin"]);
        assert_eq!(read_all(&mut vol, "/sub/big.bin"), big);
        // The hosted half's up-case table is the standard one, which this
        // driver reads off the card.
        assert_eq!(read_all(&mut vol, "/MIXED CASE.TXT"), b"tiny");
    }

    #[test]
    fn the_hosted_half_reads_what_the_driver_wrote() {
        let mut vol = Volume::<_, 512>::mount(as_card(hosted_format())).unwrap();
        vol.create_dir("/from-driver").unwrap();
        let body: Vec<u8> = (0..90_000u32).map(|i| (i % 253) as u8).collect();
        write_file(&mut vol, "/from-driver/payload.bin", &body);
        write_file(&mut vol, "/from-driver/note.txt", b"written with no heap");
        write_file(&mut vol, "/ünïcode.txt", "häuser".as_bytes());
        let card = vol.unmount().unwrap();

        let mut dev = MemoryBackend::from_bytes(card.data);
        let mut fs = Exfat::open(&mut dev).expect("hosted open");
        let listing = fs.list_path(&mut dev, "/from-driver").unwrap();
        let mut names: Vec<String> = listing.iter().map(|e| e.name.clone()).collect();
        names.sort();
        assert_eq!(names, ["note.txt", "payload.bin"]);
        assert_eq!(
            hosted_read(&mut fs, &mut dev, "/from-driver/payload.bin"),
            body
        );
        assert_eq!(
            hosted_read(&mut fs, &mut dev, "/from-driver/note.txt"),
            b"written with no heap"
        );
        assert_eq!(
            hosted_read(&mut fs, &mut dev, "/ünïcode.txt"),
            "häuser".as_bytes()
        );
    }

    #[test]
    fn both_halves_agree_after_interleaved_edits() {
        let mut vol = Volume::<_, 512>::mount(as_card(hosted_format())).unwrap();
        for i in 0..6u32 {
            write_file(
                &mut vol,
                &alloc::format!("/d{i}.bin"),
                &vec![i as u8; 5_000],
            );
        }
        let card = vol.unmount().unwrap();

        let mut dev = MemoryBackend::from_bytes(card.data);
        let mut fs = Exfat::open(&mut dev).unwrap();
        let payload = vec![0xee_u8; 20_000];
        fs.create_file(
            &mut dev,
            "/hosted.bin",
            &mut Cursor::new(payload.clone()),
            payload.len() as u64,
            0,
        )
        .unwrap();
        fs.remove(&mut dev, "/d3.bin").unwrap();
        fs.flush(&mut dev).unwrap();
        let bytes = {
            let mut out = vec![0u8; BYTES as usize];
            dev.read_at(0, &mut out).unwrap();
            out
        };

        let mut card = RamCard::new(1);
        card.data = bytes;
        let mut vol = Volume::<_, 512>::mount(card).unwrap();
        let names = list(&mut vol, "/");
        assert!(names.iter().any(|n| n == "hosted.bin"), "{names:?}");
        assert!(!names.iter().any(|n| n == "d3.bin"), "{names:?}");
        assert_eq!(read_all(&mut vol, "/hosted.bin"), payload);
        assert_eq!(read_all(&mut vol, "/d0.bin"), vec![0u8; 5_000]);

        vol.remove_file("/d5.bin").unwrap();
        write_file(&mut vol, "/after.txt", b"last word");
        let card = vol.unmount().unwrap();

        let mut dev = MemoryBackend::from_bytes(card.data);
        let mut fs = Exfat::open(&mut dev).unwrap();
        let listing = fs.list_path(&mut dev, "/").unwrap();
        let names: Vec<String> = listing.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains(&String::from("after.txt")), "{names:?}");
        assert!(!names.contains(&String::from("d5.bin")), "{names:?}");
        assert_eq!(hosted_read(&mut fs, &mut dev, "/after.txt"), b"last word");
    }
}

#[test]
fn mounts_a_volume_inside_a_gpt_partition() {
    // The GPT a PC or a card formatter writes: a protective MBR, a
    // CRC-protected header at LBA 1, and the volume somewhere in the middle
    // of the medium.
    const START: u32 = 2048;
    let sectors = 24 * 1024;
    let mut card = RamCard::new(START + sectors + 64);
    format(&mut card, START, sectors, 8);
    write_gpt(&mut card, START, sectors, gpt::BASIC_DATA);

    // Sector 0 is the protective MBR, so a whole-card mount finds nothing…
    let mut probe = RamCard::new(1);
    probe.data = card.data.clone();
    assert!(matches!(
        Volume::<_, 512>::mount(probe),
        Err(Error::NotExfat)
    ));

    // …and the probe finds the volume through the table.
    let mut card2 = RamCard::new(1);
    card2.data = card.data.clone();
    assert_eq!(
        Volume::<_, 512>::probe(&mut card2).unwrap(),
        Some(START as u64)
    );

    let mut vol = Volume::<_, 512>::mount_auto(card).unwrap();
    assert_eq!(vol.geometry().part_start, START as u64);
    write_file(&mut vol, "/in-gpt.txt", b"found through the GUID table");
    let card = vol.unmount().unwrap();
    let mut vol = Volume::<_, 512>::mount_auto(card).unwrap();
    assert_eq!(
        read_all(&mut vol, "/in-gpt.txt"),
        b"found through the GUID table"
    );
}

#[test]
fn a_gpt_whose_primary_header_is_damaged_still_mounts() {
    const START: u32 = 2048;
    let sectors = 24 * 1024;
    let mut card = RamCard::new(START + sectors + 64);
    format(&mut card, START, sectors, 8);
    write_gpt(&mut card, START, sectors, gpt::BASIC_DATA);
    // Scribble the primary header. The backup at the last sector is what the
    // format keeps a second copy for.
    card.data[512..604].fill(0x5A);

    let mut vol = Volume::<_, 512>::mount_auto(card).unwrap();
    assert_eq!(vol.geometry().part_start, START as u64);
    assert!(list(&mut vol, "/").is_empty());
}

#[test]
fn a_gpt_partition_of_an_unexpected_type_still_mounts() {
    // The type GUID is a hint: a volume in a Linux-filesystem-typed partition
    // is still an exFAT volume if its boot sector says so.
    const START: u32 = 2048;
    let sectors = 24 * 1024;
    let mut card = RamCard::new(START + sectors + 64);
    format(&mut card, START, sectors, 8);
    write_gpt(&mut card, START, sectors, gpt::LINUX_FS);
    let vol = Volume::<_, 512>::mount_auto(card).unwrap();
    assert_eq!(vol.geometry().part_start, START as u64);
}

/// Lay down a GPT over `card` describing one partition of `type_guid`:
/// protective MBR, primary header and array, and the backup pair at the end.
fn write_gpt(card: &mut RamCard, start: u32, sectors: u32, type_guid: gpt::Guid) {
    let total = card.data.len() as u64 / 512;
    // Protective MBR.
    card.data[..512].fill(0);
    card.data[446 + 4] = 0xEE;
    card.data[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    card.data[446 + 12..446 + 16].copy_from_slice(&((total - 1) as u32).to_le_bytes());
    card.data[510] = 0x55;
    card.data[511] = 0xAA;

    // One entry, in a 128-entry array.
    let mut array = vec![0u8; 128 * 128];
    array[0..16].copy_from_slice(&type_guid.0);
    array[16..32].copy_from_slice(&[0x33u8; 16]);
    array[32..40].copy_from_slice(&(start as u64).to_le_bytes());
    array[40..48].copy_from_slice(&(start as u64 + sectors as u64 - 1).to_le_bytes());
    for (i, u) in "VOLUME".encode_utf16().enumerate() {
        array[56 + i * 2..58 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    let array_crc = crate::crc::crc32(&array);
    let backup_array_lba = total - 1 - 32;
    card.data[2 * 512..][..array.len()].copy_from_slice(&array);
    card.data[backup_array_lba as usize * 512..][..array.len()].copy_from_slice(&array);

    let header = |my: u64, alt: u64, entries_lba: u64| -> [u8; 512] {
        let mut h = [0u8; 512];
        h[0..8].copy_from_slice(gpt::SIGNATURE);
        h[8..12].copy_from_slice(&gpt::REVISION.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&my.to_le_bytes());
        h[32..40].copy_from_slice(&alt.to_le_bytes());
        h[40..48].copy_from_slice(&34u64.to_le_bytes());
        h[48..56].copy_from_slice(&(total - 34).to_le_bytes());
        h[56..72].copy_from_slice(&[0x44u8; 16]);
        h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        h[80..84].copy_from_slice(&128u32.to_le_bytes());
        h[84..88].copy_from_slice(&128u32.to_le_bytes());
        h[88..92].copy_from_slice(&array_crc.to_le_bytes());
        let crc = crate::crc::crc32(&h[..92]);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    };
    card.data[512..1024].copy_from_slice(&header(1, total - 1, 2));
    card.data[(total - 1) as usize * 512..][..512].copy_from_slice(&header(
        total - 1,
        1,
        backup_array_lba,
    ));
}

// -- formatting ---------------------------------------------------------------

mod formatting {
    use super::super::format::plan;
    use super::*;
    use alloc::collections::BTreeMap;

    /// A card whose sectors exist only once written, so a many-gigabyte
    /// format is testable. Unwritten sectors read as a pattern, not zeros,
    /// so a format that leans on a blank card is caught.
    #[derive(Debug)]
    struct Sparse {
        sectors: u64,
        ss: u32,
        data: BTreeMap<u64, Vec<u8>>,
    }

    impl Sparse {
        fn new(bytes: u64, ss: u32) -> Self {
            Self {
                sectors: bytes / ss as u64,
                ss,
                data: BTreeMap::new(),
            }
        }
    }

    impl SectorDriver for Sparse {
        type Error = core::convert::Infallible;
        fn sector_size(&self) -> u32 {
            self.ss
        }
        fn sector_count(&self) -> u64 {
            self.sectors
        }
        fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
            let ss = self.ss as usize;
            assert!(buf.len().is_multiple_of(ss) && lba + (buf.len() / ss) as u64 <= self.sectors);
            for (i, chunk) in buf.chunks_mut(ss).enumerate() {
                match self.data.get(&(lba + i as u64)) {
                    Some(s) => chunk.copy_from_slice(s),
                    None => chunk.fill(0xE5),
                }
            }
            Ok(())
        }
        fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
            let ss = self.ss as usize;
            assert!(buf.len().is_multiple_of(ss) && lba + (buf.len() / ss) as u64 <= self.sectors);
            for (i, chunk) in buf.chunks(ss).enumerate() {
                self.data.insert(lba + i as u64, chunk.to_vec());
            }
            Ok(())
        }
    }

    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;

    #[test]
    fn the_cluster_size_follows_microsofts_defaults() {
        for (bytes, cluster) in [
            (8 * MIB, 4096),
            (256 * MIB, 4096),
            (2 * GIB, 32 << 10),
            (32 * GIB, 32 << 10),
            (64 * GIB, 128 << 10),
            (2048 * GIB, 128 << 10),
        ] {
            let p = plan(bytes / 512, 512, None).unwrap();
            assert_eq!(p.spc * 512, cluster, "at {bytes} bytes");
            assert!(p.fat_length as u64 * 512 >= (p.clusters as u64 + 2) * 4);
            assert_eq!(p.heap_offset % p.spc, 0, "heap on a cluster boundary");
            let heap_end = p.heap_offset as u64 + p.clusters as u64 * p.spc as u64;
            assert!(heap_end <= bytes / 512 && bytes / 512 - heap_end < p.spc as u64);
        }
        assert!(plan(1024, 512, None).is_err(), "below 1 MiB");
        assert!(plan(64 * MIB / 512, 512, Some(1000)).is_err());
        // 4 KiB sectors never get a cluster below a sector.
        assert_eq!(
            plan(64 * MIB / 4096, 4096, Some(512)).map(|p| p.spc),
            Err("cluster size must be a power of two from a sector to 32 MiB")
        );
    }

    fn fill_and_check(vol: Volume<Sparse, 4096>) -> Volume<Sparse, 4096> {
        let mut vol = vol;
        let cb = vol.cluster_bytes() as usize;
        let body: Vec<u8> = (0..cb * 3 + 17).map(|i| (i % 251) as u8).collect();
        vol.create_dir("/DCIM").unwrap();
        let mut f = vol.create_file("/DCIM/Über.bin").unwrap();
        f.write_all(&mut vol, &body).unwrap();
        f.flush(&mut vol).unwrap();
        let card = vol.unmount().unwrap();
        let mut vol = Volume::<_, 4096>::mount_auto(card).unwrap();
        let mut f = vol.open_file("/dcim/über.BIN").unwrap();
        let mut back = vec![0u8; body.len()];
        f.read_exact(&mut vol, &mut back).unwrap();
        assert_eq!(back, body);
        vol
    }

    #[test]
    fn a_formatted_card_mounts_empty_and_takes_files() {
        for (bytes, ss) in [
            (8 * MIB, 512),
            (512 * MIB, 512),
            (64 * GIB, 512),
            (256 * MIB, 4096),
        ] {
            let card = Sparse::new(bytes, ss);
            let opts = VolumeFormatOpts {
                label: "Kamera",
                volume_serial: 0xABCD_0123,
                ..Default::default()
            };
            let mut vol =
                Volume::<_, 4096>::format(card, &opts).unwrap_or_else(|e| panic!("{bytes}: {e:?}"));
            let p = plan(bytes / ss as u64, ss, None).unwrap();
            assert_eq!(vol.geometry().cluster_count, p.clusters);
            assert_eq!(vol.geometry().serial, 0xABCD_0123);
            assert_eq!(
                vol.used_clusters().unwrap(),
                p.bitmap_clusters + p.upcase_clusters + 1
            );
            assert!(vol.is_writable());
            let root = vol.root();
            assert!(
                vol.iter_dir(root).next().unwrap().is_none(),
                "a fresh root lists nothing"
            );
            fill_and_check(vol);
        }
    }

    #[test]
    fn the_full_up_case_table_folds_names_beyond_ascii() {
        let mut vol =
            Volume::<_, 512>::format(Sparse::new(16 * MIB, 512), &VolumeFormatOpts::default())
                .unwrap();
        vol.create_file("/Ωmega-ÆØÅ-Straße.txt").unwrap();
        assert!(vol.exists("/ωMEGA-æøå-STRAßE.TXT").unwrap());
        // Creating the other spelling is the same name.
        assert!(matches!(
            vol.create_file("/ωmega-æøå-straße.txt"),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn only_metadata_is_written() {
        let bytes = 64 * GIB;
        let vol = Volume::<_, 512>::format(Sparse::new(bytes, 512), &VolumeFormatOpts::default())
            .unwrap();
        let p = plan(bytes / 512, 512, None).unwrap();
        let card = vol.unmount().unwrap();
        let meta_end = p.heap_offset as u64 + p.used_for_tests() as u64 * p.spc as u64;
        assert!(
            card.data.keys().all(|&lba| lba < meta_end),
            "a data cluster was written"
        );
        assert!(card.data.len() as u64 <= meta_end);
    }

    #[test]
    fn a_bad_request_writes_nothing() {
        let card = Sparse::new(16 * MIB, 512);
        let opts = VolumeFormatOpts {
            label: "far too long a label",
            ..Default::default()
        };
        assert!(matches!(
            Volume::<_, 512>::format(card, &opts),
            Err(Error::Unsupported(_))
        ));
        let card = Sparse::new(16 * MIB, 512);
        assert!(matches!(
            Volume::<_, 512>::format_at(card, 30_000, 10_000, &VolumeFormatOpts::default()),
            Err(Error::VolumeExceedsDevice)
        ));
        let card = Sparse::new(512 * 1024, 512);
        assert!(matches!(
            Volume::<_, 512>::format(card, &VolumeFormatOpts::default()),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn a_gpt_partition_is_formatted_and_found_again() {
        use crate::device::gpt;
        let mut card = Sparse::new(4 * GIB, 512);
        let mut scratch = [0u8; 512];
        let layout = gpt::Layout::new(card.sector_count(), 512).unwrap();
        let start = layout.first_aligned_lba(512);
        let sectors = layout.last_usable_lba + 1 - start;
        let part = gpt::NewPartition::new(
            gpt::BASIC_DATA,
            gpt::Guid::random_v4([5; 16]),
            start,
            sectors,
        );
        gpt::write(
            &mut card,
            &mut scratch,
            gpt::Guid::random_v4([6; 16]),
            &[part],
        )
        .unwrap();
        let vol = Volume::<_, 4096>::format_at(card, start, sectors, &VolumeFormatOpts::default())
            .unwrap();
        assert_eq!(vol.geometry().part_start, start);
        let card = vol.unmount().unwrap();
        // PartitionOffset records where the volume is.
        assert_eq!(&card.data[&start][64..72], &start.to_le_bytes());
        let vol = fill_and_check(Volume::<_, 4096>::mount_auto(card).unwrap());
        assert_eq!(vol.geometry().part_start, start);
    }

    #[test]
    fn every_size_plans_a_consistent_layout_or_is_refused() {
        for ss in [512u32, 4096] {
            for shift in 0..45u32 {
                for d in [0i64, -1, 1, 13, -4097, 65_537] {
                    let v = (1i64 << shift) + d;
                    if v <= 0 {
                        continue;
                    }
                    let sectors = v as u64;
                    for cluster in [None, Some(ss), Some(1 << 17), Some(32 << 20)] {
                        let Ok(p) = plan(sectors, ss, cluster) else {
                            continue;
                        };
                        let heap_end = p.heap_offset as u64 + p.clusters as u64 * p.spc as u64;
                        assert!(heap_end <= sectors, "{sectors}/{ss}: {p:?}");
                        assert!(p.fat_offset >= 24 && p.fat_offset + p.fat_length <= p.heap_offset);
                        assert!(p.fat_length as u64 * ss as u64 >= (p.clusters as u64 + 2) * 4);
                        assert!(p.clusters <= layout::MAX_CLUSTER_COUNT);
                        assert!(p.root_cluster() < p.clusters + 2);
                        assert!(
                            p.bitmap_clusters as u64 * p.spc as u64 * ss as u64
                                >= (p.clusters as u64).div_ceil(8)
                        );
                    }
                }
            }
        }
    }
}
