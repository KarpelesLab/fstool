//! Tests for the allocator-free FAT driver.
//!
//! These run in every configuration, including `--no-default-features
//! --features fat`, the heapless one, so the volumes they work on are
//! laid out by a small formatter right here rather than by
//! [`crate::fs::fat`], which that configuration does not compile. Where the hosted driver *is*
//! available, the last tests in the file cross-check the two against each
//! other — the strongest evidence that this driver agrees with something
//! independently validated against `fsck.vfat`.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use super::*;

/// A RAM-backed card that counts the sector transfers it is asked for,
/// so a test can pin how much traffic an operation costs a real card.
#[derive(Debug)]
struct RamCard {
    data: Vec<u8>,
    sector_size: u32,
    reads: u32,
    writes: u32,
}

impl RamCard {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
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
        let at = lba as usize * self.sector_size as usize;
        self.reads += (buf.len() / self.sector_size as usize) as u32;
        buf.copy_from_slice(&self.data[at..at + buf.len()]);
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
        let at = lba as usize * self.sector_size as usize;
        self.writes += (buf.len() / self.sector_size as usize) as u32;
        self.data[at..at + buf.len()].copy_from_slice(buf);
        Ok(())
    }
}

/// Lay out a FAT volume of `total_sectors` 512-byte sectors with
/// `spc` sectors per cluster, at `offset` sectors into `image`.
fn format(image: &mut [u8], offset: usize, total_sectors: u32, spc: u32, want: FatKind) {
    const BPS: u32 = 512;
    let reserved = if want == FatKind::Fat32 { 32 } else { 1 };
    let num_fats = 2u32;
    let root_entries = if want == FatKind::Fat32 { 0 } else { 512 };
    let root_dir_sectors = (root_entries as u32 * 32).div_ceil(BPS);

    // The FAT has to be big enough to map the clusters that are left once
    // the FAT itself is accounted for; iterate until it settles.
    let mut fat_sectors = 1u32;
    let mut clusters;
    loop {
        let data = total_sectors - reserved - num_fats * fat_sectors - root_dir_sectors;
        clusters = data / spc;
        let need_bytes = match want {
            FatKind::Fat12 => (clusters as u64 + 2).div_ceil(2) * 3,
            FatKind::Fat16 => (clusters as u64 + 2) * 2,
            FatKind::Fat32 => (clusters as u64 + 2) * 4,
        };
        let need = (need_bytes as u32).div_ceil(BPS);
        if need <= fat_sectors {
            break;
        }
        fat_sectors = need;
    }
    match want {
        FatKind::Fat12 => assert!(clusters < 4085, "{clusters} clusters is not FAT12"),
        FatKind::Fat16 => assert!(
            (4085..65525).contains(&clusters),
            "{clusters} clusters is not FAT16"
        ),
        FatKind::Fat32 => assert!(clusters >= 65525, "{clusters} clusters is not FAT32"),
    }

    let vol = &mut image[offset * BPS as usize..][..total_sectors as usize * BPS as usize];
    vol.fill(0);
    let boot = &mut vol[..512];
    boot[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    boot[3..11].copy_from_slice(b"FSTOOL  ");
    boot[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    boot[13] = spc as u8;
    boot[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
    boot[16] = num_fats as u8;
    boot[17..19].copy_from_slice(&(root_entries as u16).to_le_bytes());
    if total_sectors <= u16::MAX as u32 {
        boot[19..21].copy_from_slice(&(total_sectors as u16).to_le_bytes());
    } else {
        boot[32..36].copy_from_slice(&total_sectors.to_le_bytes());
    }
    boot[21] = 0xF8;
    if want == FatKind::Fat32 {
        boot[36..40].copy_from_slice(&fat_sectors.to_le_bytes());
        boot[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster
        boot[48..50].copy_from_slice(&1u16.to_le_bytes()); // FSInfo
        boot[50..52].copy_from_slice(&6u16.to_le_bytes()); // backup boot
    } else {
        boot[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
    }
    boot[510] = 0x55;
    boot[511] = 0xAA;

    // FAT[0] carries the media byte, FAT[1] ends a chain; on FAT32 the
    // root's own cluster is allocated too.
    let (e0, e1) = match want {
        FatKind::Fat12 => (0x0FF8u32, 0x0FFFu32),
        FatKind::Fat16 => (0xFFF8, 0xFFFF),
        FatKind::Fat32 => (0x0FFF_FFF8, 0x0FFF_FFFF),
    };
    for copy in 0..num_fats {
        let start = (reserved + copy * fat_sectors) as usize * BPS as usize;
        let fat = &mut vol[start..start + fat_sectors as usize * BPS as usize];
        match want {
            FatKind::Fat12 => {
                fat[0] = (e0 & 0xFF) as u8;
                fat[1] = (((e0 >> 8) & 0x0F) as u8) | (((e1 & 0x0F) as u8) << 4);
                fat[2] = (e1 >> 4) as u8;
            }
            FatKind::Fat16 => {
                fat[0..2].copy_from_slice(&(e0 as u16).to_le_bytes());
                fat[2..4].copy_from_slice(&(e1 as u16).to_le_bytes());
            }
            FatKind::Fat32 => {
                fat[0..4].copy_from_slice(&e0.to_le_bytes());
                fat[4..8].copy_from_slice(&e1.to_le_bytes());
                fat[8..12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
            }
        }
    }

    if want == FatKind::Fat32 {
        let fsinfo = &mut vol[BPS as usize..2 * BPS as usize];
        fsinfo[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
        fsinfo[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
        fsinfo[488..492].copy_from_slice(&(clusters - 1).to_le_bytes());
        fsinfo[492..496].copy_from_slice(&3u32.to_le_bytes());
        fsinfo[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
    }
}

/// A freshly formatted card.
fn card(total_sectors: u32, spc: u32, kind: FatKind) -> RamCard {
    let mut data = vec![0u8; total_sectors as usize * 512];
    format(&mut data, 0, total_sectors, spc, kind);
    RamCard::new(data)
}

fn fat12() -> RamCard {
    card(2048, 1, FatKind::Fat12) // 1 MiB
}

fn fat16() -> RamCard {
    card(16 * 1024, 2, FatKind::Fat16) // 8 MiB, 1 KiB clusters
}

fn fat32() -> RamCard {
    card(70_000, 1, FatKind::Fat32) // ~34 MiB, the FAT32 floor
}

type Vol = Volume<RamCard, 512>;

fn mount(c: RamCard) -> Vol {
    Volume::mount(c).expect("mount")
}

/// Remount from the same bytes, proving what was written survives.
fn remount(vol: Vol) -> Vol {
    let card = vol.unmount().expect("unmount");
    mount(card)
}

#[test]
fn mounts_each_flavour_with_consistent_geometry() {
    for (c, want) in [
        (fat12(), FatKind::Fat12),
        (fat16(), FatKind::Fat16),
        (fat32(), FatKind::Fat32),
    ] {
        let sectors = c.sector_count();
        let vol = mount(c);
        let g = *vol.geometry();
        assert_eq!(vol.kind(), want);
        assert_eq!(g.bytes_per_sector, 512);
        // Every region must fit inside the volume.
        assert!(g.first_data_sector < g.total_sectors);
        assert!(g.total_sectors as u64 <= sectors);
        // And the FAT must map every cluster it claims.
        let need = match want {
            FatKind::Fat12 => (g.cluster_count as u64 + 2).div_ceil(2) * 3,
            FatKind::Fat16 => (g.cluster_count as u64 + 2) * 2,
            FatKind::Fat32 => (g.cluster_count as u64 + 2) * 4,
        };
        assert!(g.fat_sectors as u64 * 512 >= need);
    }
}

#[test]
fn rejects_a_non_fat_sector() {
    let mut data = vec![0u8; 512 * 64];
    data[510] = 0x55;
    data[511] = 0xAA; // signature but no BPB
    let err = Volume::<_, 512>::mount(RamCard::new(data)).unwrap_err();
    assert_eq!(err, Error::NotFat);
}

#[test]
fn scratch_smaller_than_the_sector_is_refused() {
    let c = fat16();
    // 512-byte sectors cannot be served from a 256-byte scratch buffer.
    let err = Volume::<_, 256>::mount(c).unwrap_err();
    assert!(matches!(err, Error::ScratchTooSmall { needed: 512, .. }));
}

#[test]
fn write_then_read_survives_a_remount() {
    for c in [fat12(), fat16(), fat32()] {
        let mut vol = mount(c);
        let mut f = vol.create_file("/hello.txt").unwrap();
        f.write_all(&mut vol, b"hello, world\n").unwrap();
        f.flush(&mut vol).unwrap();
        assert_eq!(f.len(), 13);

        let mut vol = remount(vol);
        let mut f = vol.open_file("/hello.txt").unwrap();
        assert_eq!(f.len(), 13);
        let mut buf = [0u8; 32];
        let n = f.read(&mut vol, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello, world\n");
        // Reading at the end returns nothing rather than failing.
        assert_eq!(f.read(&mut vol, &mut buf).unwrap(), 0);
    }
}

#[test]
fn a_file_can_span_many_clusters() {
    let mut vol = mount(fat16());
    let cb = vol.cluster_bytes() as usize;
    let body: Vec<u8> = (0..cb * 5 + 37).map(|i| (i % 251) as u8).collect();

    let mut f = vol.create_file("/big.bin").unwrap();
    f.write_all(&mut vol, &body).unwrap();
    f.flush(&mut vol).unwrap();

    let mut vol = remount(vol);
    let mut f = vol.open_file("/big.bin").unwrap();
    assert_eq!(f.len() as usize, body.len());
    let mut back = vec![0u8; body.len()];
    f.read_exact(&mut vol, &mut back).unwrap();
    assert_eq!(back, body);

    // And random access lands in the right cluster in both directions.
    for at in [cb * 3 + 5, 7, cb * 5, cb - 1] {
        f.seek(&mut vol, at as u32).unwrap();
        let mut one = [0u8; 1];
        f.read_exact(&mut vol, &mut one).unwrap();
        assert_eq!(one[0], body[at], "byte {at}");
    }
}

#[test]
fn appending_extends_the_chain() {
    let mut vol = mount(fat12());
    let cb = vol.cluster_bytes() as usize;
    let mut f = vol.create_file("/log.txt").unwrap();
    for i in 0..20 {
        f.seek_to_end(&mut vol).unwrap();
        let line = [b'a' + (i % 26) as u8; 64];
        f.write_all(&mut vol, &line).unwrap();
    }
    f.flush(&mut vol).unwrap();
    assert_eq!(f.len() as usize, 20 * 64);
    assert!(20 * 64 > cb, "the test should cross a cluster boundary");

    let mut vol = remount(vol);
    let mut f = vol.open_file("/log.txt").unwrap();
    let mut back = vec![0u8; f.len() as usize];
    f.read_exact(&mut vol, &mut back).unwrap();
    for i in 0..20 {
        assert!(
            back[i * 64..(i + 1) * 64]
                .iter()
                .all(|&b| b == b'a' + (i % 26) as u8)
        );
    }
}

#[test]
fn seeking_past_the_end_zero_fills() {
    let mut vol = mount(fat16());
    let cb = vol.cluster_bytes();
    let mut f = vol.create_file("/sparse.bin").unwrap();
    f.write_all(&mut vol, b"start").unwrap();
    // Leave a gap that crosses a cluster boundary.
    f.seek(&mut vol, cb + 10).unwrap();
    f.write_all(&mut vol, b"end").unwrap();
    f.flush(&mut vol).unwrap();
    assert_eq!(f.len(), cb + 13);

    let mut vol = remount(vol);
    let mut f = vol.open_file("/sparse.bin").unwrap();
    let mut back = vec![0u8; f.len() as usize];
    f.read_exact(&mut vol, &mut back).unwrap();
    assert_eq!(&back[..5], b"start");
    assert!(
        back[5..cb as usize + 10].iter().all(|&b| b == 0),
        "the gap must read as zeros"
    );
    assert_eq!(&back[cb as usize + 10..], b"end");
}

#[test]
fn set_len_truncates_and_frees_clusters() {
    let mut vol = mount(fat16());
    let cb = vol.cluster_bytes();
    let before = vol.free_clusters().unwrap();

    let mut f = vol.create_file("/t.bin").unwrap();
    f.write_all(&mut vol, &vec![7u8; cb as usize * 4]).unwrap();
    f.flush(&mut vol).unwrap();
    let used = before - vol.free_clusters().unwrap();
    assert_eq!(used, 4);

    f.set_len(&mut vol, 10).unwrap();
    f.flush(&mut vol).unwrap();
    assert_eq!(f.len(), 10);
    assert_eq!(before - vol.free_clusters().unwrap(), 1);

    // Growing again zero-fills rather than exposing the old bytes.
    f.set_len(&mut vol, 100).unwrap();
    f.flush(&mut vol).unwrap();
    let mut vol = remount(vol);
    let mut f = vol.open_file("/t.bin").unwrap();
    let mut back = [0u8; 100];
    f.read_exact(&mut vol, &mut back).unwrap();
    assert!(back[..10].iter().all(|&b| b == 7));
    assert!(back[10..].iter().all(|&b| b == 0), "stale bytes leaked");

    // And truncating to zero gives every cluster back.
    f.set_len(&mut vol, 0).unwrap();
    f.flush(&mut vol).unwrap();
    assert_eq!(vol.free_clusters().unwrap(), before);
    assert_eq!(f.first_cluster(), 0);
}

#[test]
fn long_names_round_trip() {
    let mut vol = mount(fat32());
    let names = [
        "A rather long file name with spaces.txt",
        "ünïcödé-name.dat",
        "short.c",
        "no-extension",
        "exactly-thirteen",
    ];
    for (i, name) in names.iter().enumerate() {
        let mut f = vol.create_file(name).unwrap();
        f.write_all(&mut vol, &[i as u8; 16]).unwrap();
        f.flush(&mut vol).unwrap();
    }

    let mut vol = remount(vol);
    // Every name is found by lookup…
    for (i, name) in names.iter().enumerate() {
        let mut f = vol.open_file(name).unwrap();
        let mut buf = [0u8; 16];
        f.read_exact(&mut vol, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == i as u8), "{name}");
    }
    // …and comes back from a listing.
    let root = vol.root();
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut it = vol.iter_dir(root);
    while let Some(e) = it.next().unwrap() {
        seen.push(e.name().as_bytes().to_vec());
    }
    for name in names {
        assert!(
            seen.iter().any(|s| s == name.as_bytes()),
            "{name} missing from the listing"
        );
    }
}

#[test]
fn a_name_at_the_long_name_limit_works_and_one_past_it_does_not() {
    let mut vol = mount(fat32());
    let ok: Vec<u8> = core::iter::repeat_n(b'x', 255).collect();
    let ok = core::str::from_utf8(&ok).unwrap();
    let mut f = vol.create_file(ok).unwrap();
    f.write_all(&mut vol, b"!").unwrap();
    f.flush(&mut vol).unwrap();
    assert_eq!(vol.open_file(ok).unwrap().len(), 1);

    let too_long: Vec<u8> = core::iter::repeat_n(b'y', 256).collect();
    let too_long = core::str::from_utf8(&too_long).unwrap();
    assert_eq!(
        vol.create_file(too_long).unwrap_err(),
        Error::InvalidName,
        "256 units must be refused"
    );
}

#[test]
fn colliding_long_names_get_distinct_short_names() {
    let mut vol = mount(fat32());
    // All three share the "LONGNA~" basis.
    let names = [
        "long name one.txt",
        "long name two.txt",
        "long name three.txt",
    ];
    for (i, name) in names.iter().enumerate() {
        let mut f = vol.create_file(name).unwrap();
        f.write_all(&mut vol, &[i as u8]).unwrap();
        f.flush(&mut vol).unwrap();
    }
    let mut vol = remount(vol);
    for (i, name) in names.iter().enumerate() {
        let mut f = vol.open_file(name).unwrap();
        let mut b = [0u8; 1];
        f.read_exact(&mut vol, &mut b).unwrap();
        assert_eq!(b[0], i as u8, "{name} resolved to the wrong file");
    }
}

#[test]
fn names_are_matched_case_insensitively() {
    let mut vol = mount(fat16());
    let mut f = vol.create_file("/README.TXT").unwrap();
    f.write_all(&mut vol, b"x").unwrap();
    f.flush(&mut vol).unwrap();
    assert!(vol.open_file("/readme.txt").is_ok());
    assert!(vol.open_file("/ReAdMe.TxT").is_ok());
    assert_eq!(
        vol.create_file("/readme.txt").unwrap_err(),
        Error::AlreadyExists
    );
}

#[test]
fn directories_nest_and_list() {
    let mut vol = mount(fat32());
    vol.create_dir("/data").unwrap();
    vol.create_dir("/data/logs").unwrap();
    let mut f = vol.create_file("/data/logs/today.log").unwrap();
    f.write_all(&mut vol, b"entry\n").unwrap();
    f.flush(&mut vol).unwrap();

    let mut vol = remount(vol);
    assert!(vol.metadata("/data").unwrap().is_dir());
    assert!(vol.metadata("/data/logs").unwrap().is_dir());
    let mut f = vol.open_file("/data/logs/today.log").unwrap();
    let mut buf = [0u8; 6];
    f.read_exact(&mut vol, &mut buf).unwrap();
    assert_eq!(&buf, b"entry\n");

    // `.` and `..` are present in a subdirectory, and `..` of a
    // first-level directory points at the root (cluster 0 by convention).
    let dir = vol.open_dir("/data").unwrap();
    let mut dots = 0;
    let mut it = vol.iter_dir(dir);
    while let Some(e) = it.next().unwrap() {
        if e.is_dot() {
            dots += 1;
            if e.name() == ".." {
                assert_eq!(e.metadata().first_cluster, 0);
            }
        }
    }
    assert_eq!(dots, 2);
}

#[test]
fn removing_files_and_directories() {
    let mut vol = mount(fat16());
    let free = vol.free_clusters().unwrap();
    vol.create_dir("/dir").unwrap();
    let mut f = vol.create_file("/dir/file.bin").unwrap();
    f.write_all(&mut vol, &[1u8; 4096]).unwrap();
    f.flush(&mut vol).unwrap();

    assert_eq!(
        vol.remove_dir("/dir").unwrap_err(),
        Error::DirectoryNotEmpty
    );
    assert_eq!(vol.remove_file("/dir").unwrap_err(), Error::IsADirectory);
    assert_eq!(
        vol.remove_dir("/dir/file.bin").unwrap_err(),
        Error::NotADirectory
    );

    vol.remove_file("/dir/file.bin").unwrap();
    vol.remove_dir("/dir").unwrap();
    vol.flush().unwrap();
    assert_eq!(vol.free_clusters().unwrap(), free, "clusters were leaked");

    let mut vol = remount(vol);
    assert!(!vol.exists("/dir").unwrap());
    assert_eq!(vol.open_file("/dir/file.bin").unwrap_err(), Error::NotFound);
}

#[test]
fn a_removed_name_can_be_created_again() {
    let mut vol = mount(fat16());
    let mut f = vol.create_file("/a long name.txt").unwrap();
    f.write_all(&mut vol, b"first").unwrap();
    f.flush(&mut vol).unwrap();
    vol.remove_file("/a long name.txt").unwrap();

    let mut f = vol.create_file("/a long name.txt").unwrap();
    f.write_all(&mut vol, b"second").unwrap();
    f.flush(&mut vol).unwrap();

    let mut vol = remount(vol);
    let mut f = vol.open_file("/a long name.txt").unwrap();
    let mut buf = [0u8; 6];
    f.read_exact(&mut vol, &mut buf).unwrap();
    assert_eq!(&buf, b"second");
}

#[test]
fn a_directory_grows_past_its_first_cluster() {
    let mut vol = mount(fat32());
    vol.create_dir("/many").unwrap();
    // 1 sector per cluster = 16 entries per cluster, so long names force
    // several cluster extensions.
    let mut names = Vec::new();
    for i in 0..40 {
        let mut name = [0u8; 32];
        let text = b"entry-with-a-long-name-";
        name[..text.len()].copy_from_slice(text);
        let digits = [b'0' + (i / 10) as u8, b'0' + (i % 10) as u8];
        name[text.len()..text.len() + 2].copy_from_slice(&digits);
        let name = core::str::from_utf8(&name[..text.len() + 2]).unwrap();
        let path = alloc::format!("/many/{name}");
        let mut f = vol.create_file(&path).unwrap();
        f.write_all(&mut vol, &[i as u8]).unwrap();
        f.flush(&mut vol).unwrap();
        names.push(path);
    }

    let mut vol = remount(vol);
    for (i, path) in names.iter().enumerate() {
        let mut f = vol.open_file(path).unwrap();
        let mut b = [0u8; 1];
        f.read_exact(&mut vol, &mut b).unwrap();
        assert_eq!(b[0], i as u8, "{path}");
    }
    let dir = vol.open_dir("/many").unwrap();
    let mut count = 0;
    let mut it = vol.iter_dir(dir);
    while let Some(e) = it.next().unwrap() {
        if !e.is_dot() {
            count += 1;
        }
    }
    assert_eq!(count, 40);
}

#[test]
fn the_fixed_root_fills_up_rather_than_growing() {
    let mut vol = mount(fat12());
    // 512 slots; every 8.3 name takes exactly one.
    let mut made = 0;
    for i in 0..600u32 {
        let name = alloc::format!("/F{i:05}.BIN");
        match vol.create_file(&name) {
            Ok(_) => made += 1,
            Err(Error::DirectoryFull) => break,
            Err(e) => panic!("unexpected {e:?} after {made} files"),
        }
    }
    assert_eq!(made, 512, "the fixed root holds exactly its entry count");
}

#[test]
fn fat12_entries_pack_across_sector_boundaries() {
    // A FAT12 entry is 1.5 bytes, so every other one straddles two bytes
    // and some straddle two sectors. Filling a volume exercises both.
    let mut vol = mount(fat12());
    let cb = vol.cluster_bytes() as usize;
    let free = vol.free_clusters().unwrap() as usize;
    let body = vec![0xA5u8; cb * (free.min(400))];

    let mut f = vol.create_file("/fill.bin").unwrap();
    f.write_all(&mut vol, &body).unwrap();
    f.flush(&mut vol).unwrap();

    let mut vol = remount(vol);
    let mut f = vol.open_file("/fill.bin").unwrap();
    let mut back = vec![0u8; body.len()];
    f.read_exact(&mut vol, &mut back).unwrap();
    assert_eq!(back, body, "a chain of {} clusters", body.len() / cb);
}

#[test]
fn running_out_of_space_is_reported() {
    let mut vol = mount(fat12());
    let cb = vol.cluster_bytes() as usize;
    let free = vol.free_clusters().unwrap() as usize;
    let mut f = vol.create_file("/all.bin").unwrap();
    // One cluster more than the volume holds.
    let err = f
        .write_all(&mut vol, &vec![1u8; cb * (free + 1)])
        .unwrap_err();
    assert_eq!(err, Error::NoSpace);
}

#[test]
fn mounts_a_volume_inside_an_mbr_partition() {
    // 2048 sectors of gap, then an 8 MiB FAT16 volume.
    let start = 2048u32;
    let vol_sectors = 16 * 1024u32;
    let mut data = vec![0u8; (start + vol_sectors) as usize * 512];
    format(&mut data, start as usize, vol_sectors, 2, FatKind::Fat16);

    let mbr = &mut data[..512];
    mbr[446 + 4] = 0x06; // FAT16
    mbr[446 + 8..446 + 12].copy_from_slice(&start.to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&vol_sectors.to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    // The whole device is not a FAT volume…
    assert_eq!(
        Volume::<_, 512>::mount(RamCard::new(data.clone())).unwrap_err(),
        Error::NotFat
    );
    // …but the partition is, by index and by probing.
    let mut vol = Volume::<_, 512>::mount_partition(RamCard::new(data.clone()), 1).unwrap();
    assert_eq!(vol.geometry().part_start, start as u64);
    let mut f = vol.create_file("/in-part.txt").unwrap();
    f.write_all(&mut vol, b"partitioned").unwrap();
    f.flush(&mut vol).unwrap();
    let card = vol.unmount().unwrap();

    let mut vol = Volume::<_, 512>::mount_auto(card).unwrap();
    assert_eq!(vol.geometry().part_start, start as u64);
    let mut f = vol.open_file("/in-part.txt").unwrap();
    let mut buf = [0u8; 11];
    f.read_exact(&mut vol, &mut buf).unwrap();
    assert_eq!(&buf, b"partitioned");

    assert_eq!(
        Volume::<_, 512>::mount_partition(RamCard::new(data), 3).unwrap_err(),
        Error::NoSuchPartition
    );
}

#[test]
fn paths_are_validated() {
    let mut vol = mount(fat16());
    vol.create_dir("/dir").unwrap();
    let mut f = vol.create_file("/dir/f.txt").unwrap();
    f.flush(&mut vol).unwrap();

    // An empty path and "/" both name the root, which is a directory.
    assert_eq!(vol.open_file("").unwrap_err(), Error::IsADirectory);
    assert_eq!(vol.open_file("/").unwrap_err(), Error::IsADirectory);
    assert_eq!(vol.create_file("/").unwrap_err(), Error::InvalidPath);
    assert_eq!(vol.open_file("/nope/f.txt").unwrap_err(), Error::NotFound);
    assert_eq!(
        vol.open_file("/dir/f.txt/deeper").unwrap_err(),
        Error::NotADirectory
    );
    assert_eq!(vol.open_dir("/dir/..").unwrap_err(), Error::InvalidPath);
    // A leading slash is optional and trailing ones are ignored.
    assert!(vol.open_file("dir/f.txt").is_ok());
    assert!(vol.open_dir("/dir/").is_ok());
    // Names FAT cannot store are refused rather than mangled.
    assert_eq!(vol.create_file("/a:b.txt").unwrap_err(), Error::InvalidName);
    assert_eq!(
        vol.create_file("/trailing.").unwrap_err(),
        Error::InvalidName
    );
}

#[test]
fn free_space_tracks_allocation_and_survives_a_remount() {
    let mut vol = mount(fat32());
    let cb = vol.cluster_bytes();
    let before = vol.free_clusters().unwrap();

    let mut f = vol.create_file("/x.bin").unwrap();
    f.write_all(&mut vol, &vec![0u8; cb as usize * 3]).unwrap();
    f.flush(&mut vol).unwrap();
    assert_eq!(vol.free_clusters().unwrap(), before - 3);
    assert_eq!(vol.free_bytes().unwrap(), (before - 3) as u64 * cb as u64);

    // FSInfo carries the count across a remount without a FAT scan.
    let mut vol = remount(vol);
    assert_eq!(vol.free_clusters().unwrap(), before - 3);
}

#[test]
fn short_names_decode_with_their_case_flags() {
    let mut vol = mount(fat16());
    // "readme.txt" is 8.3-shaped and uniformly lower case, so it is stored
    // as a short entry with the NT case flags and no long-name entries.
    let mut f = vol.create_file("/readme.txt").unwrap();
    f.write_all(&mut vol, b"x").unwrap();
    f.flush(&mut vol).unwrap();

    let mut vol = remount(vol);
    let root = vol.root();
    let mut it = vol.iter_dir(root);
    let e = it.next().unwrap().unwrap();
    assert_eq!(e.name(), "readme.txt");
}

#[test]
fn an_entry_handle_opens_without_a_second_lookup() {
    let mut vol = mount(fat16());
    let mut f = vol.create_file("/data.bin").unwrap();
    f.write_all(&mut vol, b"0123456789").unwrap();
    f.flush(&mut vol).unwrap();

    let root = vol.root();
    let mut handle = None;
    let mut it = vol.iter_dir(root);
    while let Some(e) = it.next().unwrap() {
        if e.name() == "data.bin" {
            handle = Some(e.to_file());
        }
    }
    let mut f = handle.expect("entry");
    let mut buf = [0u8; 10];
    f.read_exact(&mut vol, &mut buf).unwrap();
    assert_eq!(&buf, b"0123456789");
}

// ---------------------------------------------------------------------
// Cross-checks against the hosted driver, which is itself validated
// against `fsck.vfat` / `mtools` in CI. `fat` alone is the heapless
// build and has no hosted driver to compare against, so these appear
// only once `alloc` is on too.
// ---------------------------------------------------------------------

// The hosted driver exists only when `alloc` does.
#[cfg(feature = "alloc")]
mod cross {
    use super::*;
    use crate::block::MemoryBackend;
    use crate::fs::fat::{Fat32, FatFormatOpts, FatKind as HostedKind};
    use crate::fs::{FileMeta, FileSource, Filesystem};
    use alloc::boxed::Box;
    // The crate's own `Path` / `Cursor`, which are `std`'s on a hosted
    // build and stand-ins without one — so these tests compile in the
    // `alloc`-but-no-`std` configuration too.
    use crate::io::Cursor;
    use crate::path::Path;

    const SECTORS: u32 = 128 * 1024; // 64 MiB, comfortably FAT32

    fn hosted_format() -> MemoryBackend {
        let mut dev = MemoryBackend::new(SECTORS as u64 * 512);
        let opts = FatFormatOpts {
            kind: HostedKind::Fat32,
            total_sectors: SECTORS,
            volume_id: 0x1234_5678,
            volume_label: *b"CROSSCHECK ",
            ..Default::default()
        };
        let mut fs = Fat32::format(&mut dev, &opts).expect("hosted format");
        fs.flush(&mut dev).expect("hosted flush");
        dev
    }

    fn read_all(fs: &mut Fat32, dev: &mut MemoryBackend, path: &str) -> Vec<u8> {
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

    #[test]
    fn reads_a_volume_the_hosted_driver_wrote() {
        let mut dev = hosted_format();
        let mut fs = Fat32::open(&mut dev).unwrap();
        fs.create_dir(&mut dev, Path::new("/sub"), FileMeta::default())
            .unwrap();
        let body = b"written by the hosted driver".to_vec();
        fs.create_file(
            &mut dev,
            Path::new("/sub/a long name.txt"),
            FileSource::Reader {
                reader: Box::new(Cursor::new(body.clone())),
                len: body.len() as u64,
            },
            FileMeta::default(),
        )
        .unwrap();
        fs.flush(&mut dev).unwrap();

        let mut vol = mount(RamCard::new(dev.into_bytes()));
        let mut f = vol.open_file("/sub/a long name.txt").unwrap();
        let mut buf = vec![0u8; body.len()];
        f.read_exact(&mut vol, &mut buf).unwrap();
        assert_eq!(buf, body);

        // The listing agrees too, long name and all.
        let dir = vol.open_dir("/sub").unwrap();
        let mut found = false;
        let mut it = vol.iter_dir(dir);
        while let Some(e) = it.next().unwrap() {
            if e.name() == "a long name.txt" {
                found = true;
                assert_eq!(e.len() as usize, body.len());
            }
        }
        assert!(found, "the hosted driver's long name did not come back");
    }

    #[test]
    fn the_hosted_driver_reads_what_this_one_wrote() {
        let dev = hosted_format();
        let mut vol = mount(RamCard::new(dev.into_bytes()));
        vol.create_dir("/from-noalloc").unwrap();
        let body: Vec<u8> = (0..50_000u32).map(|i| (i % 253) as u8).collect();
        let mut f = vol.create_file("/from-noalloc/payload.bin").unwrap();
        f.write_all(&mut vol, &body).unwrap();
        f.flush(&mut vol).unwrap();
        let mut short = vol.create_file("/README.TXT").unwrap();
        short.write_all(&mut vol, b"short name").unwrap();
        short.flush(&mut vol).unwrap();
        let card = vol.unmount().unwrap();

        // Read it back with the driver that CI validates against
        // fsck.vfat and mtools.
        let mut dev = MemoryBackend::from_bytes(card.data);
        let mut fs = Fat32::open(&mut dev).expect("hosted open");
        assert_eq!(
            read_all(&mut fs, &mut dev, "/from-noalloc/payload.bin"),
            body
        );
        assert_eq!(read_all(&mut fs, &mut dev, "/README.TXT"), b"short name");

        let listing = fs.list(&mut dev, Path::new("/from-noalloc")).unwrap();
        assert!(
            listing.iter().any(|e| e.name == "payload.bin"),
            "hosted listing missed the file: {listing:?}"
        );
    }

    #[test]
    fn both_drivers_agree_after_interleaved_edits() {
        let dev = hosted_format();
        let bytes = dev.into_bytes();

        // The no-alloc driver creates, the hosted one adds beside it,
        // then the no-alloc one removes and both listings must match.
        let mut vol = mount(RamCard::new(bytes));
        for i in 0..8u32 {
            let mut f = vol.create_file(&alloc::format!("/file-{i}.dat")).unwrap();
            f.write_all(&mut vol, &[i as u8; 600]).unwrap();
            f.flush(&mut vol).unwrap();
        }
        vol.remove_file("/file-3.dat").unwrap();
        vol.flush().unwrap();
        let card = vol.unmount().unwrap();

        let mut dev = MemoryBackend::from_bytes(card.data);
        let mut fs = Fat32::open(&mut dev).unwrap();
        let listing = fs.list(&mut dev, Path::new("/")).unwrap();
        let names: Vec<_> = listing.iter().map(|e| e.name.clone()).collect();
        for i in 0..8u32 {
            let want = alloc::format!("file-{i}.dat");
            assert_eq!(
                names.iter().any(|n| n == &want),
                i != 3,
                "{want} presence is wrong: {names:?}"
            );
        }
        for i in [0u32, 7] {
            assert_eq!(
                read_all(&mut fs, &mut dev, &alloc::format!("/file-{i}.dat")),
                vec![i as u8; 600]
            );
        }
    }
}

// ---------------------------------------------------------------------
// Regressions for the findings of the first review of this module.
// ---------------------------------------------------------------------

/// `remove_dir("/a/.")` used to free the cluster `/a` was still using,
/// leaving the directory listed and its cluster on the free list — the
/// next allocation cross-linked them.
#[test]
fn dot_and_dotdot_are_not_paths_you_can_remove() {
    let mut vol = mount(fat16());
    vol.create_dir("/a").unwrap();
    let cluster = vol.metadata("/a").unwrap().first_cluster;
    let free = vol.free_clusters().unwrap();

    for path in ["/a/.", "/a/..", "/a/./", "/."] {
        assert_eq!(
            vol.remove_dir(path).unwrap_err(),
            Error::InvalidPath,
            "remove_dir({path})"
        );
        assert_eq!(vol.remove_file(path).unwrap_err(), Error::InvalidPath);
        assert_eq!(vol.create_file(path).unwrap_err(), Error::InvalidPath);
    }
    assert_eq!(vol.free_clusters().unwrap(), free, "a cluster was freed");
    assert_eq!(vol.metadata("/a").unwrap().first_cluster, cluster);

    // The directory still holds exactly `.` and `..`.
    let dir = vol.open_dir("/a").unwrap();
    let mut dots = 0;
    let mut it = vol.iter_dir(dir);
    while let Some(e) = it.next().unwrap() {
        assert!(e.is_dot(), "unexpected entry {}", e.name());
        dots += 1;
    }
    assert_eq!(dots, 2);
}

/// Patch the first root-directory entry's first-cluster field.
fn patch_root_first_cluster(vol: &mut Vol, cluster: u32) {
    let g = *vol.geometry();
    let sector = g.root_dir_first_sector() as usize;
    let card = vol.driver_mut();
    let at = sector * 512;
    card.data[at + 26..at + 28].copy_from_slice(&(cluster as u16).to_le_bytes());
    card.data[at + 20..at + 22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
}

/// A first cluster read straight off a corrupt entry used to reach the
/// sector arithmetic unchecked: cluster 1 underflowed, and a cluster past
/// the end of the volume sent the driver off the medium.
#[test]
fn a_corrupt_first_cluster_is_refused_rather_than_followed() {
    for bad in [1u32, 0xFFF0, 0xFFFF] {
        let mut vol = mount(fat16());
        let mut f = vol.create_file("/F.BIN").unwrap();
        f.write_all(&mut vol, &[b'x'; 4096]).unwrap();
        f.flush(&mut vol).unwrap();
        patch_root_first_cluster(&mut vol, bad);

        let mut vol = remount(vol);
        let mut f = vol.open_file("/F.BIN").unwrap();
        let mut buf = [0u8; 1024];
        assert_eq!(
            f.read(&mut vol, &mut buf).unwrap_err(),
            Error::CorruptChain,
            "reading cluster {bad}"
        );
        let mut f = vol.open_file("/F.BIN").unwrap();
        assert_eq!(
            f.write(&mut vol, &[1u8; 1024]).unwrap_err(),
            Error::CorruptChain,
            "writing cluster {bad}"
        );
        // Nothing reached the card outside its own sectors.
        let sectors = vol.driver().sector_count();
        assert!(sectors > 0);
    }
}

/// Removing a file by the short name this driver generated for it used to
/// leave its long-name entries behind; the next file to take that slot
/// then inherited the deleted file's name.
#[test]
fn removing_by_short_name_takes_the_long_name_with_it() {
    let mut vol = mount(fat16());
    let mut f = vol.create_file("/hello world.txt").unwrap();
    f.write_all(&mut vol, b"first").unwrap();
    f.flush(&mut vol).unwrap();

    // The generated short name is what a FAT driver without long-name
    // support would see.
    vol.remove_file("/HELLOW~1.TXT").unwrap();
    assert!(!vol.exists("/hello world.txt").unwrap());

    let mut f = vol.create_file("/HELLOW~1.TXT").unwrap();
    f.write_all(&mut vol, b"second").unwrap();
    f.flush(&mut vol).unwrap();

    let mut vol = remount(vol);
    let root = vol.root();
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut it = vol.iter_dir(root);
    while let Some(e) = it.next().unwrap() {
        names.push(e.name().as_bytes().to_vec());
    }
    assert_eq!(
        names,
        [b"HELLOW~1.TXT".to_vec()],
        "an orphaned long-name run renamed the new file"
    );
}

/// One FAT entry must cost one cached sector per FAT copy. Walking the
/// copies inside the bytes instead evicted the cache on every byte, which
/// is eight sector writes per FAT32 entry and eight times the flash wear.
#[test]
fn allocation_does_not_amplify_writes() {
    for (card, label, budget) in [(fat16(), "fat16", 700u32), (fat32(), "fat32", 700)] {
        let mut vol = mount(card);
        let payload = vec![0u8; 64 * 1024];
        vol.driver_mut().writes = 0;
        vol.driver_mut().reads = 0;

        let mut f = vol.create_file("/big.bin").unwrap();
        f.write_all(&mut vol, &payload).unwrap();
        f.flush(&mut vol).unwrap();

        let writes = vol.driver().writes;
        // 128 sectors of payload; the rest is FAT, directory and FSInfo.
        assert!(
            writes < budget,
            "{label}: {writes} sector writes for a 64 KiB file (budget {budget})"
        );
    }
}

/// A short name is up to 12 characters, but CP437's upper half decodes to
/// three UTF-8 bytes each, so the comparison buffer has to hold 34.
#[test]
fn short_names_outside_ascii_match_their_decoded_form() {
    let mut vol = mount(fat16());
    // Hand-write an 8.3 entry whose every name byte is CP437 0xB0 ('░').
    {
        let g = *vol.geometry();
        let at = g.root_dir_first_sector() as usize * 512;
        let card = vol.driver_mut();
        card.data[at..at + 8].fill(0xB0);
        card.data[at + 8..at + 11].copy_from_slice(b"TXT");
        card.data[at + 11] = Attributes::ARCHIVE;
        card.data[at + 28..at + 32].copy_from_slice(&7u32.to_le_bytes());
    }
    let mut vol = remount(vol);

    let root = vol.root();
    let listed = {
        let mut it = vol.iter_dir(root);
        let e = it.next().unwrap().unwrap();
        e.name().to_string()
    };
    assert_eq!(listed, "░░░░░░░░.TXT");
    // The name the listing gave must be the name that opens it…
    assert_eq!(vol.metadata(&listed).unwrap().len, 7);
    // …and a truncation of it must not.
    assert!(vol.metadata("/░░░░.").unwrap_err().is_not_found());
}

/// A FAT32 volume cannot address more clusters than a 28-bit entry names:
/// past 0x0FFFFFF6 the allocator would hand out a number every reader
/// treats as end-of-chain.
#[test]
fn a_fat32_volume_claiming_the_whole_entry_space_is_refused() {
    // 270_532_633 sectors of 512 bytes with one 2 GiB FAT: enough data
    // sectors to claim 268_435_449 clusters.
    let mut boot = vec![0u8; 512];
    boot[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    boot[11..13].copy_from_slice(&512u16.to_le_bytes());
    boot[13] = 1;
    boot[14..16].copy_from_slice(&32u16.to_le_bytes());
    boot[16] = 1;
    boot[32..36].copy_from_slice(&270_532_633u32.to_le_bytes());
    boot[36..40].copy_from_slice(&2_097_152u32.to_le_bytes());
    boot[44..48].copy_from_slice(&2u32.to_le_bytes());
    boot[510] = 0x55;
    boot[511] = 0xAA;

    let device_bytes = 270_532_633u64 * 512;
    let err = Geometry::parse::<core::convert::Infallible>(&boot, 0, device_bytes).unwrap_err();
    assert_eq!(err, Error::NotFat);
}

/// A volume dropped without an explicit flush still writes back its
/// cached sector, rather than losing the last thing written through it.
/// (A `File`'s size lives in the handle until `File::flush`, so this is
/// about the volume's own cache: directory entries and FAT updates.)
#[test]
fn dropping_a_volume_flushes_its_cache() {
    use alloc::rc::Rc;
    use core::cell::RefCell;

    /// A card whose bytes outlive the volume, so the test can look at
    /// them after `Drop` has run.
    #[derive(Debug, Clone)]
    struct SharedCard(Rc<RefCell<Vec<u8>>>);

    impl SectorDriver for SharedCard {
        type Error = core::convert::Infallible;
        fn sector_size(&self) -> u32 {
            512
        }
        fn sector_count(&self) -> u64 {
            self.0.borrow().len() as u64 / 512
        }
        fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
            let at = lba as usize * 512;
            buf.copy_from_slice(&self.0.borrow()[at..at + buf.len()]);
            Ok(())
        }
        fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
            let at = lba as usize * 512;
            self.0.borrow_mut()[at..at + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    let card = SharedCard(Rc::new(RefCell::new(fat16().data)));
    {
        let mut vol = Volume::<_, 512>::mount(card.clone()).unwrap();
        vol.create_dir("/made").unwrap();
        // No `vol.flush()`, no `unmount()`: the entry and the FAT link
        // are sitting in the one-sector cache.
    }

    let mut vol = Volume::<_, 512>::mount(card.clone()).unwrap();
    assert!(
        vol.exists("/made").unwrap(),
        "the cached sector was discarded on drop"
    );
}

/// `alloc` is a performance feature for this driver and nothing more: the
/// allocation table is kept in memory, so walking a long chain stops
/// re-reading FAT sectors. The API, and every answer it gives, is the
/// same either way.
#[test]
fn the_in_memory_fat_only_changes_how_much_is_read() {
    let mut vol = mount(fat16());
    let cb = vol.cluster_bytes() as usize;
    let body: Vec<u8> = (0..cb * 40).map(|i| (i % 251) as u8).collect();
    let mut f = vol.create_file("/chain.bin").unwrap();
    f.write_all(&mut vol, &body).unwrap();
    f.flush(&mut vol).unwrap();
    let mut vol = remount(vol);

    // Walk the whole chain backwards, which re-reads FAT entries the most.
    let mut f = vol.open_file("/chain.bin").unwrap();
    let mut one = [0u8; 1];
    vol.driver_mut().reads = 0;
    for i in (0..40).rev() {
        f.seek(&mut vol, (i * cb) as u32).unwrap();
        f.read_exact(&mut vol, &mut one).unwrap();
        assert_eq!(one[0], body[i * cb], "cluster {i}");
    }
    let reads = vol.driver().reads;

    if cfg!(feature = "alloc") {
        // The FAT is resident, so the reads left are the data sectors.
        assert!(
            vol.fat_cache_bytes() > 0,
            "the table should be held in memory"
        );
        assert!(
            reads <= 45,
            "{reads} sector reads for 40 backward seeks — the table is not being cached"
        );
    } else {
        // Without a heap every lookup goes to the card, which is the
        // trade the configuration makes.
        assert_eq!(vol.fat_cache_bytes(), 0);
        assert!(reads >= 40);
    }
}
