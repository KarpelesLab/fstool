//! Shared write helper: a bumping cursor over a device. The format
//! writers (zip / cpio / ar) own one of these and stream headers +
//! bodies through it, exactly like tar's `TarWriter`.
//!
//! Bounds are the device's business, not the cursor's: a fixed-capacity
//! device (`FileBackend`, `MemoryBackend::new`) rejects a write past its
//! end with `OutOfBounds`, and a growable one
//! (`MemoryBackend::growable`) extends — which is the point of handing a
//! streaming writer a device that starts at 0 bytes. Snapshotting
//! `total_size()` at construction would turn the second case into an
//! error on the first header.

use crate::Result;
use crate::block::BlockDevice;

/// A monotonic write cursor over a device.
pub struct Cursor {
    pos: u64,
}

impl Cursor {
    pub fn new(_dev: &dyn BlockDevice) -> Self {
        Self { pos: 0 }
    }

    /// Current write position (== bytes written so far).
    pub fn position(&self) -> u64 {
        self.pos
    }

    /// Append `buf` at the cursor, advancing it. A fixed-capacity device
    /// reports an overrun as `OutOfBounds`; a growable one extends.
    pub fn write(&mut self, dev: &mut dyn BlockDevice, buf: &[u8]) -> Result<()> {
        dev.write_at(self.pos, buf)?;
        self.pos += buf.len() as u64;
        Ok(())
    }
}
