//! Feed arbitrary media to `fs::volume::probe` and `mount_found`.
//!
//! The probe decides which driver gets a medium by reading signatures off
//! it — an exFAT boot sector, a FAT BPB, a littlefs superblock log — at the
//! start of the medium and of every partition a GPT or MBR names. All of
//! that is untrusted, and so is the geometry it hands on: a littlefs block
//! size, a partition's extent. Whatever the bytes, the answer must be a
//! volume or an error — never a panic, never a read outside the medium.
//!
//! Run with:
//!   cargo +nightly fuzz run volume_mount

#![no_main]

use fstool::device::SectorDriver;
use fstool::fs::volume::{self, Volume, VolumeDirIter, VolumeFile};
use libfuzzer_sys::fuzz_target;

/// A RAM medium that treats a read or write outside it as a finding.
struct Disk(Vec<u8>);

impl SectorDriver for Disk {
    type Error = core::convert::Infallible;

    fn sector_size(&self) -> u32 {
        512
    }

    fn sector_count(&self) -> u64 {
        self.0.len() as u64 / 512
    }

    fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        assert!(buf.len().is_multiple_of(512) && !buf.is_empty(), "partial sector");
        let at = lba as usize * 512;
        assert!(at + buf.len() <= self.0.len(), "read past the medium");
        buf.copy_from_slice(&self.0[at..at + buf.len()]);
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), Self::Error> {
        assert!(buf.len().is_multiple_of(512) && !buf.is_empty(), "partial sector");
        let at = lba as usize * 512;
        assert!(at + buf.len() <= self.0.len(), "write past the medium");
        self.0[at..at + buf.len()].copy_from_slice(buf);
        Ok(())
    }
}

/// 1 MiB: room for a partition table and small volumes of every kind.
const SECTORS: usize = 2048;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    // The first byte picks where the fuzzer's bytes land, so partitions
    // and whole-medium volumes are both reachable; the rest tiles the
    // medium from there.
    let mut image = vec![0u8; SECTORS * 512];
    let start = (data[0] as usize % 4) * 512 * 63;
    for chunk in image[start..].chunks_mut(data.len() - 1) {
        chunk.copy_from_slice(&data[1..1 + chunk.len()]);
    }
    let mut dev = Disk(image);

    let Ok(Some(found)) = volume::probe::<_, 512>(&mut dev) else {
        return;
    };
    let Ok(mut vol) = volume::mount_found::<_, 512, 4096>(dev, found) else {
        return;
    };
    let _ = (vol.fs_type(), vol.total_bytes());

    // List the root and read a little of each file in it.
    let root = vol.root();
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut it = vol.iter_dir(root);
    while let Ok(Some(e)) = it.next() {
        names.push(e.name().to_vec());
        if names.len() >= 64 {
            break;
        }
    }
    drop(it);
    for name in names {
        let Ok(name) = String::from_utf8(name) else {
            continue;
        };
        let path = format!("/{name}");
        let _ = vol.metadata(&path);
        if let Ok(mut f) = vol.open_file(&path) {
            let mut buf = [0u8; 256];
            let _ = f.read(&mut vol, &mut buf);
        }
    }
    let _ = vol.free_bytes();
});
