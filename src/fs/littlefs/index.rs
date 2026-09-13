//! CTZ skip-list arithmetic — how littlefs maps a file offset to a block.
//!
//! A file's blocks form a reversed skip-list: block *n* starts with
//! `ctz(n)+1` pointers, the *x*-th of which points at block *n*-2ˣ, and the
//! rest of the block is file data. Only the *last* block (the "head") and
//! the file size are recorded in the metadata, which is enough to reach any
//! offset in O(log n) reads and — crucially for a copy-on-write filesystem —
//! means rewriting the file from some offset onward leaves every earlier
//! block untouched and still correctly pointed at.
//!
//! The first eight blocks of a file, with the pointers each one stores:
//!
//! ```text
//!   index   pointers stored at the start of the block
//!   ----------------------------------------------------
//!     0     (none — the whole block is data)
//!     1     → 0
//!     2     → 1, 0
//!     3     → 2
//!     4     → 3, 2, 0
//!     5     → 4
//!     6     → 5, 4
//!     7     → 6
//! ```
//!
//! Reaching index 0 from index 7 is then three hops (7 → 6 → 4 → 0)
//! rather than seven.
//!
//! Nothing here touches a device or allocates: it is the shared arithmetic
//! both halves of the backend walk their skip-lists with.

/// Number of skip pointers stored at the start of block `index`.
pub fn pointers(index: u32) -> u32 {
    if index == 0 {
        0
    } else {
        index.trailing_zeros() + 1
    }
}

/// Bytes of file data block `index` can hold.
pub fn payload(block_size: u32, index: u32) -> u32 {
    block_size - 4 * pointers(index)
}

/// `ceil(log2(a))`, littlefs's `lfs_npw2`.
pub fn npw2(a: u32) -> u32 {
    32 - a.wrapping_sub(1).leading_zeros()
}

/// Map a file offset to `(block index, offset within that block)`. The
/// in-block offset includes the skip pointers, so it is the byte position to
/// read from directly.
///
/// This is `lfs_ctz_index`: the pointer overhead of the preceding blocks is
/// a population count, because block *n* carries `ctz(n)+1` pointers and
/// `Σ ctz(k) = n - popcount(n)`.
pub fn index_of(block_size: u32, off: u32) -> (u32, u32) {
    let b = block_size - 2 * 4;
    let i = off / b;
    if i == 0 {
        return (0, off);
    }
    let i = off.saturating_sub(4 * ((i - 1).count_ones() + 2)) / b;
    let o = off - b * i - 4 * i.count_ones();
    (i, o)
}

/// File offset the data in block `index` starts at.
///
/// The inverse of [`index_of`]: every earlier block contributes a full
/// block minus its own skip pointers, and `Σ ctz(k) = n - popcount(n)`
/// collapses that sum into a population count.
pub fn block_start(block_size: u32, index: u32) -> u32 {
    if index == 0 {
        return 0;
    }
    index * (block_size - 8) + 8 + 4 * (index - 1).count_ones()
}

/// The skip pointer to follow to get from block index `current` to a block
/// at or after `target`, as a `(slot, blocks skipped)` pair.
///
/// Each hop follows the largest pointer that doesn't overshoot, which is
/// what makes a seek O(log n) reads rather than O(n).
pub fn hop(current: u32, target: u32) -> (u32, u32) {
    let skip = npw2(current - target + 1)
        .saturating_sub(1)
        .min(current.trailing_zeros());
    (skip, 1 << skip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_math_agrees_with_block_capacities() {
        // Walking the file offset by offset must land on exactly the block
        // sequence the capacities imply — this is the invariant that keeps
        // reads and writes pointing at the same bytes.
        let bs = 256;
        let mut off = 0u32;
        for index in 0..40u32 {
            let cap = payload(bs, index);
            for within in 0..cap {
                let (i, o) = index_of(bs, off);
                assert_eq!(i, index, "offset {off} should be in block {index}");
                assert_eq!(o, 4 * pointers(index) + within);
                off += 1;
            }
        }
    }

    #[test]
    fn first_block_holds_a_whole_block() {
        assert_eq!(payload(4096, 0), 4096);
        assert_eq!(index_of(4096, 0), (0, 0));
        assert_eq!(index_of(4096, 4095), (0, 4095));
        // Block 1 carries one pointer, so its data starts at byte 4.
        assert_eq!(index_of(4096, 4096), (1, 4));
    }

    #[test]
    fn block_start_inverts_index_of() {
        for index in 0..64u32 {
            let start = block_start(512, index);
            assert_eq!(index_of(512, start), (index, 4 * pointers(index)));
            if index > 0 {
                // The byte before is the last of the previous block.
                assert_eq!(index_of(512, start - 1).0, index - 1);
            }
        }
    }

    #[test]
    fn pointer_counts_follow_ctz() {
        assert_eq!(pointers(0), 0);
        assert_eq!(pointers(1), 1);
        assert_eq!(pointers(2), 2);
        assert_eq!(pointers(3), 1);
        assert_eq!(pointers(4), 3);
        assert_eq!(pointers(8), 4);
    }

    #[test]
    fn npw2_matches_ceil_log2() {
        assert_eq!(npw2(1), 0);
        assert_eq!(npw2(2), 1);
        assert_eq!(npw2(3), 2);
        assert_eq!(npw2(4), 2);
        assert_eq!(npw2(5), 3);
    }

    #[test]
    fn a_hop_never_overshoots_and_always_advances() {
        for current in 1..64u32 {
            for target in 0..current {
                let (slot, step) = hop(current, target);
                assert!(step >= 1, "{current}→{target} made no progress");
                assert!(
                    current - step >= target,
                    "{current}→{target} overshot by slot {slot}"
                );
                // The slot has to exist in the block we are hopping from.
                assert!(slot < pointers(current), "{current} has no slot {slot}");
            }
        }
    }
}
