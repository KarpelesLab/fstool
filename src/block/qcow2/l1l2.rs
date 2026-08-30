//! L1 + L2 cluster mapping tables.
//!
//! qcow2's L1/L2 indirection is a two-level page table for the virtual
//! → physical cluster mapping:
//!
//! ```text
//!   cluster_idx = virtual_offset >> cluster_bits
//!   l2_entries  = cluster_size / 8           // u64 entries per L2 cluster
//!   l1_idx      = cluster_idx / l2_entries
//!   l2_idx      = cluster_idx % l2_entries
//! ```
//!
//! - L1 is small (one entry per L2 cluster), loaded in full at open.
//! - L2 is per-table-cluster; we cache the ones we've touched.
//!
//! Entry bit layout (same for L1 and L2):
//!
//! ```text
//!   63       COPIED   refcount == 1, no COW needed
//!   62       COMPRESSED (L2 only)
//!   9..55    cluster offset
//!   0        ZERO (L2 only, v3+): the cluster reads as zeros
//!   else     reserved (must be 0)
//! ```
//!
//! The ZERO bit matters most with a backing file: it is how an image says
//! "this range is genuinely zero" as opposed to "I have nothing here, ask
//! the backing file". An unallocated cluster falls through to the backing
//! file; a zero cluster does not. qcow2 v2 has no such bit, so a v2 image
//! over a backing file must allocate and write real zeros instead.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::Result;

use super::header::Header;

/// Where the cluster backing a virtual address physically lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mapping {
    /// No physical cluster. Reads return zeros — or, when the image has a
    /// backing file, whatever the backing file holds there.
    Unallocated,
    /// Plain cluster at this physical byte offset (cluster-aligned).
    Normal(u64),
    /// The ZERO flag is set: the cluster reads as zeros regardless of any
    /// backing file. `host_offset` is the preallocated cluster the flag
    /// rides on, or 0 when the entry carries no allocation.
    Zero { host_offset: u64 },
    /// Compressed cluster: `byte_len` compressed bytes start at
    /// `host_offset` (byte-granular, may straddle clusters).
    Compressed { host_offset: u64, byte_len: u64 },
}

/// Set when refcount == 1 — we own the cluster outright.
pub const COPIED: u64 = 1u64 << 63;
/// L2-only: compressed cluster.
pub const COMPRESSED: u64 = 1u64 << 62;
/// L2-only, qcow2 v3 and later: the cluster reads as all zeros.
pub const ZERO: u64 = 1u64 << 0;
/// Mask isolating the cluster-aligned physical byte offset.
pub const OFFSET_MASK: u64 = 0x00FF_FFFF_FFFF_FE00;

/// In-memory L1 + L2 mapping state.
pub struct L1L2 {
    pub cluster_size: u64,
    pub cluster_bits: u32,
    /// Number of u64 entries that fit in one L2 cluster.
    pub l2_entries: usize,
    /// In-memory copy of the L1 table.
    pub l1: Vec<u64>,
    /// Byte offset of the L1 table on disk.
    pub l1_table_offset: u64,
    /// Cached L2 tables, keyed by physical L2 cluster offset.
    pub l2_cache: HashMap<u64, L2Entry>,
    /// L2 cache size cap (number of cached L2 clusters). Old entries
    /// are dropped on insert. Set high enough that linear-scan workloads
    /// don't thrash.
    pub l2_cache_cap: usize,
    /// True for qcow2 v3+, where L2 bit 0 marks a zero cluster. On a v2
    /// image that bit is reserved and must be ignored.
    pub zero_flag: bool,
}

pub struct L2Entry {
    pub entries: Vec<u64>,
    pub dirty: bool,
}

impl L1L2 {
    /// Load the L1 table from disk. The caller is responsible for
    /// seeking — this method reads `header.l1_size` u64 BE entries
    /// starting at `header.l1_table_offset`.
    pub fn load<F: Read + Seek>(file: &mut F, header: &Header) -> Result<Self> {
        let cluster_size = header.cluster_size();
        let l2_entries = (cluster_size / 8) as usize;

        // `l1_size` is attacker-controlled; `l1_size * 8` is allocated up front
        // before any bounds-checked read. The L1 table must physically fit
        // within the file, so bounding its byte size against the file length
        // caps the allocation (a small malicious image cannot force a large
        // reservation). We deliberately do NOT require `l1_size` to equal the
        // minimum entries needed to map the virtual size — valid images
        // (including our own writer) legitimately over-provision the L1 table.
        let l1_bytes = (header.l1_size as u64)
            .checked_mul(8)
            .ok_or_else(|| crate::Error::InvalidImage("qcow2: l1_size * 8 overflows".into()))?;
        let file_len = file.seek(SeekFrom::End(0))?;
        if l1_bytes > file_len {
            return Err(crate::Error::InvalidImage(format!(
                "qcow2: L1 table ({l1_bytes} bytes) exceeds file length {file_len}"
            )));
        }
        let l1_bytes = l1_bytes as usize;
        file.seek(SeekFrom::Start(header.l1_table_offset))?;
        let mut raw = vec![0u8; l1_bytes];
        file.read_exact(&mut raw)?;
        let mut l1 = Vec::with_capacity(header.l1_size as usize);
        for chunk in raw.chunks_exact(8) {
            l1.push(u64::from_be_bytes(chunk.try_into().unwrap()));
        }
        Ok(Self {
            cluster_size,
            cluster_bits: header.cluster_bits,
            l2_entries,
            l1,
            l1_table_offset: header.l1_table_offset,
            l2_cache: HashMap::new(),
            l2_cache_cap: 32,
            zero_flag: header.version >= 3,
        })
    }

    /// Split a virtual byte offset into the L1 index, the L2 index, and
    /// the byte offset within the cluster.
    pub fn split_addr(&self, vaddr: u64) -> (usize, usize, u64) {
        let cluster_idx = vaddr >> self.cluster_bits;
        let l1_idx = (cluster_idx as usize) / self.l2_entries;
        let l2_idx = (cluster_idx as usize) % self.l2_entries;
        let in_cluster = vaddr & (self.cluster_size - 1);
        (l1_idx, l2_idx, in_cluster)
    }

    /// Look up the physical byte offset of the cluster containing `vaddr`.
    /// Returns `Ok(None)` when the cluster is unallocated (read should
    /// return zeros) and `Err(Unsupported)` when the L2 entry has the
    /// COMPRESSED bit set. Write/zero paths that don't yet handle
    /// compression use this; readers use [`Self::map`].
    pub fn lookup<F: Read + Seek>(&mut self, file: &mut F, vaddr: u64) -> Result<Option<u64>> {
        match self.map(file, vaddr)? {
            Mapping::Unallocated | Mapping::Zero { .. } => Ok(None),
            Mapping::Normal(phys) => Ok(Some(phys)),
            Mapping::Compressed { .. } => Err(crate::Error::Unsupported(
                "qcow2: compressed clusters are not supported".into(),
            )),
        }
    }

    /// Map the cluster containing `vaddr` to its physical placement,
    /// distinguishing unallocated, plain, and compressed clusters. A
    /// compressed cluster reports the (byte-granular, *not* cluster-aligned)
    /// host offset and the compressed byte length spanning whole 512-byte
    /// sectors — feed those to `compress::decompress_cluster`.
    pub fn map<F: Read + Seek>(&mut self, file: &mut F, vaddr: u64) -> Result<Mapping> {
        let (l1_idx, l2_idx, _) = self.split_addr(vaddr);
        if l1_idx >= self.l1.len() {
            return Ok(Mapping::Unallocated);
        }
        let l1_entry = self.l1[l1_idx];
        let l2_cluster_off = l1_entry & OFFSET_MASK;
        if l2_cluster_off == 0 {
            return Ok(Mapping::Unallocated);
        }
        let cluster_bits = self.cluster_bits;
        let l2 = self.load_l2(file, l2_cluster_off)?;
        let l2_entry = l2.entries[l2_idx];
        if l2_entry & COMPRESSED != 0 {
            // Bit layout: x = 62 - (cluster_bits - 8); host byte offset in the
            // low x bits; the next (cluster_bits-8) bits hold (nb_sectors - 1).
            let x = 62 - (cluster_bits - 8);
            let host_offset = l2_entry & ((1u64 << x) - 1);
            let sec_mask = (1u64 << (cluster_bits - 8)) - 1;
            let nb_sectors = ((l2_entry >> x) & sec_mask) + 1;
            let byte_len = nb_sectors * 512 - (host_offset & 511);
            return Ok(Mapping::Compressed {
                host_offset,
                byte_len,
            });
        }
        let phys = l2_entry & OFFSET_MASK;
        if self.zero_flag && l2_entry & ZERO != 0 {
            // Reads as zeros whether or not a cluster is preallocated
            // behind the flag, and — crucially — without consulting a
            // backing file.
            return Ok(Mapping::Zero { host_offset: phys });
        }
        if phys == 0 {
            return Ok(Mapping::Unallocated);
        }
        Ok(Mapping::Normal(phys))
    }

    fn load_l2<F: Read + Seek>(&mut self, file: &mut F, l2_off: u64) -> Result<&L2Entry> {
        if !self.l2_cache.contains_key(&l2_off) {
            file.seek(SeekFrom::Start(l2_off))?;
            let mut raw = vec![0u8; self.cluster_size as usize];
            file.read_exact(&mut raw)?;
            let entries: Vec<u64> = raw
                .chunks_exact(8)
                .map(|c| u64::from_be_bytes(c.try_into().unwrap()))
                .collect();
            if self.l2_cache.len() >= self.l2_cache_cap {
                // Drop one entry — pick the first non-dirty to evict.
                // (Simple policy; if everything's dirty we don't evict.)
                let victim = self
                    .l2_cache
                    .iter()
                    .find(|(_, v)| !v.dirty)
                    .map(|(k, _)| *k);
                if let Some(k) = victim {
                    self.l2_cache.remove(&k);
                }
            }
            self.l2_cache.insert(
                l2_off,
                L2Entry {
                    entries,
                    dirty: false,
                },
            );
        }
        Ok(self.l2_cache.get(&l2_off).unwrap())
    }

    /// Install a mapping for the cluster containing `vaddr` to point at
    /// `physical_offset`. Marks the affected L2 dirty. The caller must
    /// have already allocated the data cluster and (if needed) the L2
    /// cluster, and updated the L1 entry via [`Self::set_l1`].
    pub fn set_l2_entry(&mut self, l2_cluster_off: u64, l2_idx: usize, value: u64) -> Result<()> {
        let entry = self.l2_cache.get_mut(&l2_cluster_off).ok_or_else(|| {
            crate::Error::InvalidImage(format!(
                "qcow2: L2 cluster {l2_cluster_off:#x} not in cache; load it first"
            ))
        })?;
        entry.entries[l2_idx] = value;
        entry.dirty = true;
        Ok(())
    }

    /// Set `L1[l1_idx]` = value and mark the L1 table for flush.
    /// (Phase A doesn't write; this is for Phase B's allocator.)
    pub fn set_l1(&mut self, l1_idx: usize, value: u64) {
        self.l1[l1_idx] = value;
    }

    /// Look up `vaddr`'s mapping for *writing*: if no L1/L2 entry exists,
    /// allocate the L2 cluster (via `alloc_data_cluster`) and (later)
    /// the data cluster. Returns the cluster offset of the L2 table
    /// covering `vaddr` (allocated if needed) and the in-L2 index.
    /// The caller follows up with a data-cluster allocation.
    pub fn ensure_l2<F: Read + Write + Seek>(
        &mut self,
        file: &mut F,
        vaddr: u64,
        alloc_cluster: &mut dyn FnMut(&mut F) -> Result<u64>,
    ) -> Result<(u64, usize)> {
        let (l1_idx, l2_idx, _) = self.split_addr(vaddr);
        if l1_idx >= self.l1.len() {
            return Err(crate::Error::OutOfBounds {
                offset: vaddr,
                len: self.cluster_size,
                size: (self.l1.len() as u64) * (self.l2_entries as u64) * self.cluster_size,
            });
        }
        let l1_entry = self.l1[l1_idx];
        let l2_off = l1_entry & OFFSET_MASK;
        if l2_off == 0 {
            // Allocate a new L2 cluster.
            let l2_cluster_idx = alloc_cluster(file)?;
            let new_l2_off = l2_cluster_idx * self.cluster_size;
            self.insert_empty_l2(new_l2_off);
            self.l1[l1_idx] = new_l2_off | COPIED;
            return Ok((new_l2_off, l2_idx));
        }
        // Make sure the L2 is in cache so set_l2_entry can find it.
        let _ = self.load_l2(file, l2_off)?;
        Ok((l2_off, l2_idx))
    }

    /// Write every dirty L2 cluster back to disk, then the L1 table.
    pub fn flush<F: Write + Seek>(&mut self, file: &mut F) -> Result<()> {
        for (&off, entry) in self.l2_cache.iter_mut() {
            if !entry.dirty {
                continue;
            }
            let mut raw = vec![0u8; self.cluster_size as usize];
            for (i, &e) in entry.entries.iter().enumerate() {
                raw[i * 8..i * 8 + 8].copy_from_slice(&e.to_be_bytes());
            }
            file.seek(SeekFrom::Start(off))?;
            file.write_all(&raw)?;
            entry.dirty = false;
        }
        // Re-emit the L1 table. Always — small + cheap.
        let mut raw = vec![0u8; self.l1.len() * 8];
        for (i, &e) in self.l1.iter().enumerate() {
            raw[i * 8..i * 8 + 8].copy_from_slice(&e.to_be_bytes());
        }
        file.seek(SeekFrom::Start(self.l1_table_offset))?;
        file.write_all(&raw)?;
        Ok(())
    }

    /// Insert a freshly-allocated L2 cluster into the cache (all zeros).
    /// Caller must update the L1 entry and persist via [`Self::flush`].
    pub fn insert_empty_l2(&mut self, l2_cluster_off: u64) {
        self.l2_cache.insert(
            l2_cluster_off,
            L2Entry {
                entries: vec![0u64; self.l2_entries],
                dirty: true,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_addr_math() {
        let l = L1L2 {
            cluster_size: 65536,
            cluster_bits: 16,
            l2_entries: 8192,
            l1: vec![0; 4],
            l1_table_offset: 0,
            l2_cache: HashMap::new(),
            l2_cache_cap: 32,
            zero_flag: true,
        };
        // Cluster 0 → L1[0], L2[0], offset 0.
        assert_eq!(l.split_addr(0), (0, 0, 0));
        // Cluster 1 → L1[0], L2[1], offset 0.
        assert_eq!(l.split_addr(65536), (0, 1, 0));
        // Middle of cluster 1.
        assert_eq!(l.split_addr(65536 + 1024), (0, 1, 1024));
        // Crossing into the second L1 entry: cluster 8192.
        assert_eq!(l.split_addr(8192u64 * 65536), (1, 0, 0));
    }

    #[test]
    fn offset_mask_drops_flags() {
        let entry = COPIED | 0x0001_0000;
        assert_eq!(entry & OFFSET_MASK, 0x0001_0000);
    }
}
