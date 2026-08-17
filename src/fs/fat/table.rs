//! The FAT itself — the cluster allocation table.
//!
//! A FAT is an array of entries indexed by cluster number; each entry holds
//! the *next* cluster in that file's chain, an end-of-chain marker, or 0 for
//! a free cluster. The entry *width* is what the three FAT flavours differ
//! in — 12, 16 or 32 bits ([`FatKind`]) — and it is derived from the volume's
//! data-cluster count, not from any on-disk name.
//!
//! FAT32 entries occupy 4 bytes each but only the low 28 bits are
//! meaningful; the top 4 are reserved. FAT16 entries are a plain
//! little-endian `u16`. FAT12 entries are packed 1.5 bytes each — two
//! consecutive entries share three bytes — which is why this module keeps
//! the table as normalised `u32`s in memory and only packs on
//! [`Fat::encode`].
//!
//! Entries 0 and 1 are reserved: entry 0 holds the media byte in its low
//! 8 bits with the rest set, entry 1 is the end-of-chain value and (on
//! FAT16/FAT32) also carries the "volume clean" / "no hard error" status
//! bits.

/// A free cluster. Same value for every FAT width.
pub const FREE: u32 = 0;

/// Which entry width — and therefore which FAT flavour — a volume uses.
///
/// The FAT specification defines the flavour purely by the volume's
/// data-cluster count, so this is computed from the BPB geometry rather
/// than read from the `fs_type` string (which is documentation, not a
/// signature).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatKind {
    /// 12-bit entries, packed 2-per-3-bytes. Up to 4084 data clusters.
    Fat12,
    /// 16-bit entries. 4085..=65524 data clusters.
    Fat16,
    /// 32-bit entries (28 meaningful bits). 65525 or more data clusters.
    Fat32,
}

impl FatKind {
    /// Entry width in bits.
    pub fn bits(self) -> u32 {
        match self {
            FatKind::Fat12 => 12,
            FatKind::Fat16 => 16,
            FatKind::Fat32 => 32,
        }
    }

    /// The meaningful bits of one entry — 28 for FAT32, the full width
    /// otherwise.
    pub fn entry_mask(self) -> u32 {
        match self {
            FatKind::Fat12 => 0x0000_0FFF,
            FatKind::Fat16 => 0x0000_FFFF,
            FatKind::Fat32 => 0x0FFF_FFFF,
        }
    }

    /// The end-of-chain value this writer stores (all meaningful bits set).
    pub fn eoc(self) -> u32 {
        self.entry_mask()
    }

    /// Minimum value that counts as an end-of-chain marker.
    pub fn eoc_min(self) -> u32 {
        self.entry_mask() & !0x7
    }

    /// Whether `value` marks the end of a cluster chain.
    pub fn is_eoc(self, value: u32) -> bool {
        value >= self.eoc_min()
    }

    /// The "bad cluster" marker (one below the end-of-chain range).
    pub fn bad_cluster(self) -> u32 {
        self.eoc_min() - 1
    }

    /// Smallest data-cluster count that makes a volume this flavour.
    pub fn min_clusters(self) -> u32 {
        match self {
            FatKind::Fat12 => 1,
            FatKind::Fat16 => 4085,
            FatKind::Fat32 => 65525,
        }
    }

    /// Largest data-cluster count this flavour can address. The cap is one
    /// below the first reserved/bad-cluster value.
    pub fn max_clusters(self) -> u32 {
        match self {
            FatKind::Fat12 => 4084,
            FatKind::Fat16 => 65524,
            FatKind::Fat32 => 0x0FFF_FFF4,
        }
    }

    /// Classify a volume by its data-cluster count, per the FAT
    /// specification's one true rule.
    pub fn from_cluster_count(clusters: u32) -> FatKind {
        if clusters < FatKind::Fat16.min_clusters() {
            FatKind::Fat12
        } else if clusters < FatKind::Fat32.min_clusters() {
            FatKind::Fat16
        } else {
            FatKind::Fat32
        }
    }

    /// Bytes needed on disk to hold `entries` entries (before rounding up
    /// to a whole number of sectors).
    pub fn fat_bytes(self, entries: u64) -> u64 {
        match self {
            // Two entries per three bytes; an odd count still needs the
            // whole trailing pair's second byte.
            FatKind::Fat12 => (entries * 3).div_ceil(2),
            FatKind::Fat16 => entries * 2,
            FatKind::Fat32 => entries * 4,
        }
    }

    /// How many whole entries fit in `bytes` bytes of on-disk FAT.
    pub fn entries_in(self, bytes: usize) -> usize {
        match self {
            FatKind::Fat12 => bytes * 2 / 3,
            FatKind::Fat16 => bytes / 2,
            FatKind::Fat32 => bytes / 4,
        }
    }

    /// The 8-byte `fs_type` string conventionally stored in the BPB. It is
    /// informational only — never used to identify a volume.
    pub fn fs_type_label(self) -> &'static [u8; 8] {
        match self {
            FatKind::Fat12 => b"FAT12   ",
            FatKind::Fat16 => b"FAT16   ",
            FatKind::Fat32 => b"FAT32   ",
        }
    }

    /// Lower-case name used in CLI arguments and diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            FatKind::Fat12 => "fat12",
            FatKind::Fat16 => "fat16",
            FatKind::Fat32 => "fat32",
        }
    }
}

/// An in-memory FAT, normalised to one `u32` per entry regardless of the
/// on-disk width. `entries.len()` is the table's full entry capacity (as
/// many entries as the on-disk FAT's byte length holds); only indices
/// `0..cluster_count + 2` correspond to real clusters.
#[derive(Debug, Clone)]
pub struct Fat {
    kind: FatKind,
    /// On-disk byte length of one FAT copy. Kept so `encode` reproduces
    /// exactly the region the volume reserves — for FAT12 the entry count
    /// alone doesn't determine it.
    byte_len: usize,
    entries: Vec<u32>,
}

impl Fat {
    /// A fresh FAT occupying `byte_len` on-disk bytes, all clusters free,
    /// with the two reserved entries (0 and 1) initialised for `media`.
    pub fn new(kind: FatKind, byte_len: usize, media: u8) -> Self {
        let capacity = kind.entries_in(byte_len).max(2);
        let mut entries = vec![FREE; capacity];
        entries[0] = (0xFFFF_FF00 | media as u32) & kind.entry_mask();
        entries[1] = kind.eoc();
        Self {
            kind,
            byte_len,
            entries,
        }
    }

    /// The entry width this table was built for.
    pub fn kind(&self) -> FatKind {
        self.kind
    }

    /// Total entry capacity.
    pub fn capacity(&self) -> usize {
        self.entries.len()
    }

    /// The end-of-chain value for this table's width.
    pub fn eoc(&self) -> u32 {
        self.kind.eoc()
    }

    /// Whether `value` marks the end of a cluster chain at this width.
    pub fn is_eoc(&self, value: u32) -> bool {
        self.kind.is_eoc(value)
    }

    /// Read the entry for `cluster`.
    pub fn get(&self, cluster: u32) -> u32 {
        self.entries[cluster as usize] & self.kind.entry_mask()
    }

    /// Set the entry for `cluster`. Only the meaningful bits are stored;
    /// on FAT32 the reserved top 4 bits are kept zero.
    pub fn set(&mut self, cluster: u32, value: u32) {
        self.entries[cluster as usize] = value & self.kind.entry_mask();
    }

    /// Encode into the on-disk byte image of one FAT copy.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.byte_len];
        match self.kind {
            FatKind::Fat12 => {
                // Two entries share three bytes: [e0 low 8][e1 low 4 | e0
                // high 4][e1 high 8].
                for i in (0..self.entries.len()).step_by(2) {
                    let e0 = self.entries[i] & 0xFFF;
                    let e1 = self.entries.get(i + 1).copied().unwrap_or(0) & 0xFFF;
                    let base = i / 2 * 3;
                    if base < out.len() {
                        out[base] = (e0 & 0xFF) as u8;
                    }
                    if base + 1 < out.len() {
                        out[base + 1] = (((e0 >> 8) & 0x0F) | ((e1 & 0x0F) << 4)) as u8;
                    }
                    if base + 2 < out.len() {
                        out[base + 2] = ((e1 >> 4) & 0xFF) as u8;
                    }
                }
            }
            FatKind::Fat16 => {
                for (i, &e) in self.entries.iter().enumerate() {
                    let at = i * 2;
                    if at + 2 <= out.len() {
                        out[at..at + 2].copy_from_slice(&(e as u16).to_le_bytes());
                    }
                }
            }
            FatKind::Fat32 => {
                for (i, &e) in self.entries.iter().enumerate() {
                    let at = i * 4;
                    if at + 4 <= out.len() {
                        out[at..at + 4].copy_from_slice(&e.to_le_bytes());
                    }
                }
            }
        }
        out
    }

    /// Decode from the on-disk byte image of one FAT copy.
    pub fn decode(kind: FatKind, bytes: &[u8]) -> Self {
        let capacity = kind.entries_in(bytes.len());
        let mut entries = vec![FREE; capacity];
        match kind {
            FatKind::Fat12 => {
                for (i, slot) in entries.iter_mut().enumerate() {
                    let base = i / 2 * 3;
                    *slot = if i.is_multiple_of(2) {
                        u32::from(bytes[base]) | (u32::from(bytes[base + 1] & 0x0F) << 8)
                    } else {
                        u32::from(bytes[base + 1] >> 4) | (u32::from(bytes[base + 2]) << 4)
                    };
                }
            }
            FatKind::Fat16 => {
                for (i, slot) in entries.iter_mut().enumerate() {
                    *slot = u32::from(u16::from_le_bytes(
                        bytes[i * 2..i * 2 + 2].try_into().unwrap(),
                    ));
                }
            }
            FatKind::Fat32 => {
                for (i, slot) in entries.iter_mut().enumerate() {
                    *slot = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
                }
            }
        }
        Self {
            kind,
            byte_len: bytes.len(),
            entries,
        }
    }

    /// Follow the cluster chain starting at `start`, returning every
    /// cluster in order. Stops at an end-of-chain marker; returns an error
    /// on a free/zero entry mid-chain or an obvious loop.
    ///
    /// `cluster_count` is the volume's true data-cluster count: valid
    /// clusters live in `[2, cluster_count + 2)`. The in-memory FAT is
    /// allocated in whole sectors and may hold far more entries than that,
    /// so the walk bounds itself by `cluster_count` rather than by
    /// `entries.len()` — otherwise a malformed FAT can produce a chain
    /// spanning the whole table capacity, and the buffer subsequently
    /// sized from `chain.len()` blows past the real volume size.
    pub fn chain(&self, start: u32, cluster_count: u32) -> crate::Result<Vec<u32>> {
        let max_cluster = (cluster_count as usize) + 2;
        let bound = max_cluster.min(self.entries.len());
        let mut out = Vec::new();
        let mut cur = start;
        while !self.is_eoc(cur) {
            if cur < 2 || cur as usize >= bound {
                return Err(crate::Error::InvalidImage(format!(
                    "fat: cluster {cur} out of range while walking a chain"
                )));
            }
            if out.len() > cluster_count as usize {
                return Err(crate::Error::InvalidImage(
                    "fat: cluster chain loops".into(),
                ));
            }
            out.push(cur);
            cur = self.get(cur);
            if cur == FREE {
                return Err(crate::Error::InvalidImage(
                    "fat: cluster chain hits a free cluster".into(),
                ));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_entries() {
        let fat = Fat::new(FatKind::Fat32, 1024, 0xF8);
        assert_eq!(fat.get(0), 0x0FFF_FFF8);
        assert_eq!(fat.get(1), 0x0FFF_FFFF);
        assert_eq!(fat.get(2), FREE);

        let fat = Fat::new(FatKind::Fat16, 512, 0xF8);
        assert_eq!(fat.get(0), 0xFFF8);
        assert_eq!(fat.get(1), 0xFFFF);

        let fat = Fat::new(FatKind::Fat12, 512, 0xF0);
        assert_eq!(fat.get(0), 0xFF0);
        assert_eq!(fat.get(1), 0xFFF);
    }

    #[test]
    fn set_get_roundtrip_via_bytes() {
        for kind in [FatKind::Fat12, FatKind::Fat16, FatKind::Fat32] {
            let mut fat = Fat::new(kind, 512, 0xF8);
            // A 3-cluster chain: 2 -> 3 -> 4 -> EOC.
            fat.set(2, 3);
            fat.set(3, 4);
            fat.set(4, kind.eoc());
            let decoded = Fat::decode(kind, &fat.encode());
            assert_eq!(decoded.chain(2, 60).unwrap(), vec![2, 3, 4], "{kind:?}");
        }
    }

    /// Every 12-bit value must survive the 1.5-byte packing at both parities
    /// — the nibble-splitting is the one place FAT12 can silently corrupt a
    /// chain.
    #[test]
    fn fat12_packing_covers_every_value_at_both_parities() {
        let mut fat = Fat::new(FatKind::Fat12, 4096 * 3 / 2, 0xF8);
        assert!(fat.capacity() >= 4096);
        for c in 0..4096u32 {
            fat.set(c, c);
        }
        let decoded = Fat::decode(FatKind::Fat12, &fat.encode());
        for c in 0..4096u32 {
            assert_eq!(decoded.get(c), c, "entry {c}");
        }
    }

    /// An on-disk FAT12 whose byte length isn't a multiple of 3 (a whole
    /// number of 512-byte sectors never is) must still round-trip.
    #[test]
    fn fat12_odd_byte_length_roundtrips() {
        // One sector: 512 bytes = 341 whole entries.
        let mut fat = Fat::new(FatKind::Fat12, 512, 0xF8);
        assert_eq!(fat.capacity(), 341);
        fat.set(340, 0xABC);
        let bytes = fat.encode();
        assert_eq!(bytes.len(), 512);
        assert_eq!(Fat::decode(FatKind::Fat12, &bytes).get(340), 0xABC);
    }

    #[test]
    fn eoc_classification_per_width() {
        assert!(FatKind::Fat12.is_eoc(0xFFF));
        assert!(FatKind::Fat12.is_eoc(0xFF8));
        assert!(!FatKind::Fat12.is_eoc(0xFF7)); // bad-cluster marker
        assert!(!FatKind::Fat12.is_eoc(5));
        assert!(FatKind::Fat16.is_eoc(0xFFF8));
        assert!(!FatKind::Fat16.is_eoc(0xFFF7));
        assert!(FatKind::Fat32.is_eoc(0x0FFF_FFF8));
        assert!(!FatKind::Fat32.is_eoc(0x0FFF_FFF7));
    }

    #[test]
    fn kind_from_cluster_count_follows_the_spec_thresholds() {
        assert_eq!(FatKind::from_cluster_count(1), FatKind::Fat12);
        assert_eq!(FatKind::from_cluster_count(4084), FatKind::Fat12);
        assert_eq!(FatKind::from_cluster_count(4085), FatKind::Fat16);
        assert_eq!(FatKind::from_cluster_count(65524), FatKind::Fat16);
        assert_eq!(FatKind::from_cluster_count(65525), FatKind::Fat32);
    }

    #[test]
    fn chain_detects_free_break() {
        let mut fat = Fat::new(FatKind::Fat32, 512, 0xF8);
        fat.set(2, 3); // 3 is still FREE
        assert!(fat.chain(2, 62).is_err());
    }
}
