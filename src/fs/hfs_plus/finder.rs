//! Finder metadata: the 32 bytes of `FinderInfo` every HFS+ catalog
//! record carries.
//!
//! A file record holds `FileInfo` + `ExtendedFileInfo`; a folder record
//! holds `FolderInfo` + `ExtendedFolderInfo` (TN1150, "Finder Info").
//! The two layouts agree on where the flags, the icon location, the
//! extended flags and the put-away folder live, and differ only in the
//! first eight bytes (file type + creator vs. window rectangle) and bytes
//! 16‥20 (reserved vs. scroll position). [`FinderInfo`] keeps the raw
//! bytes — exactly what macOS returns as the `com.apple.FinderInfo`
//! extended attribute — and offers typed accessors for both views.
//!
//! All multi-byte fields are big-endian.

/// `fdFlags` / `frFlags` bits (the Finder flags word at offset 8).
pub mod flags {
    /// `kIsOnDesk` — file/folder is on the desktop (System 7 only).
    pub const IS_ON_DESK: u16 = 0x0001;
    /// `kColor` — three-bit label colour mask.
    pub const COLOR_MASK: u16 = 0x000E;
    /// `kIsShared` — application may be executed by several users.
    pub const IS_SHARED: u16 = 0x0040;
    /// `kHasNoINITs` — file contains no `INIT` resources.
    pub const HAS_NO_INITS: u16 = 0x0080;
    /// `kHasBeenInited` — the Finder has recorded this item's position.
    pub const HAS_BEEN_INITED: u16 = 0x0100;
    /// `kHasCustomIcon` — a custom icon is present (a file's `icns`
    /// resource, a folder's `Icon\r` file, a volume's `.VolumeIcon.icns`).
    pub const HAS_CUSTOM_ICON: u16 = 0x0400;
    /// `kIsStationery` — file is a stationery pad.
    pub const IS_STATIONERY: u16 = 0x0800;
    /// `kNameLocked` — the name cannot be changed from the Finder.
    pub const NAME_LOCKED: u16 = 0x1000;
    /// `kHasBundle` — file has a `BNDL` resource / folder is a bundle.
    pub const HAS_BUNDLE: u16 = 0x2000;
    /// `kIsInvisible` — hidden from the Finder.
    pub const IS_INVISIBLE: u16 = 0x4000;
    /// `kIsAlias` — file is an alias.
    pub const IS_ALIAS: u16 = 0x8000;
}

/// Extended Finder flags (the word at offset 24).
pub mod extended_flags {
    /// `kExtendedFlagsAreInvalid` — ignore the other extended flags.
    pub const ARE_INVALID: u16 = 0x8000;
    /// `kExtendedFlagHasCustomBadge` — the item has a custom badge.
    pub const HAS_CUSTOM_BADGE: u16 = 0x0100;
    /// `kExtendedFlagObjectIsBusy` — the object is busy.
    pub const OBJECT_IS_BUSY: u16 = 0x0080;
    /// `kExtendedFlagHasRoutingInfo` — file has routing info.
    pub const HAS_ROUTING_INFO: u16 = 0x0004;
}

/// The 32 Finder-info bytes of one catalog record.
///
/// Construct with [`FinderInfo::default`] (all zero) or
/// [`FinderInfo::from_bytes`], adjust with the setters, and store with
/// [`super::HfsPlus::set_finder_info`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct FinderInfo {
    bytes: [u8; 32],
}

impl FinderInfo {
    /// Size of the on-disk structure.
    pub const SIZE: usize = 32;

    /// Wrap 32 raw bytes (as stored in the catalog, or as read from a
    /// `com.apple.FinderInfo` xattr).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Build from a slice that must be exactly 32 bytes long.
    pub fn from_slice(b: &[u8]) -> crate::Result<Self> {
        let bytes: [u8; 32] = b.try_into().map_err(|_| {
            crate::Error::InvalidArgument(format!(
                "hfs+: FinderInfo must be exactly 32 bytes, got {}",
                b.len()
            ))
        })?;
        Ok(Self { bytes })
    }

    /// The raw bytes.
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Mutably borrow the raw bytes, for fields without an accessor.
    pub fn as_bytes_mut(&mut self) -> &mut [u8; 32] {
        &mut self.bytes
    }

    /// `true` when every byte is zero.
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    fn u16_at(&self, off: usize) -> u16 {
        u16::from_be_bytes([self.bytes[off], self.bytes[off + 1]])
    }

    fn set_u16_at(&mut self, off: usize, v: u16) {
        self.bytes[off..off + 2].copy_from_slice(&v.to_be_bytes());
    }

    fn i16_at(&self, off: usize) -> i16 {
        self.u16_at(off) as i16
    }

    fn set_i16_at(&mut self, off: usize, v: i16) {
        self.set_u16_at(off, v as u16);
    }

    fn u32_at(&self, off: usize) -> u32 {
        u32::from_be_bytes(self.bytes[off..off + 4].try_into().unwrap())
    }

    fn set_u32_at(&mut self, off: usize, v: u32) {
        self.bytes[off..off + 4].copy_from_slice(&v.to_be_bytes());
    }

    // -- common to files and folders ---------------------------------

    /// Finder flags (`fdFlags` / `frFlags`); see [`flags`].
    pub fn finder_flags(&self) -> u16 {
        self.u16_at(8)
    }

    /// Replace the Finder flags.
    pub fn set_finder_flags(&mut self, v: u16) {
        self.set_u16_at(8, v)
    }

    /// Icon position in the parent window, `(v, h)` (`fdLocation` /
    /// `frLocation`).
    pub fn location(&self) -> (i16, i16) {
        (self.i16_at(10), self.i16_at(12))
    }

    /// Set the icon position, `(v, h)`.
    pub fn set_location(&mut self, v: i16, h: i16) {
        self.set_i16_at(10, v);
        self.set_i16_at(12, h);
    }

    /// Label colour index 0‥7 (bits 1‥3 of the Finder flags).
    pub fn label_color(&self) -> u8 {
        ((self.finder_flags() & flags::COLOR_MASK) >> 1) as u8
    }

    /// Set the label colour index (0‥7; higher bits are ignored).
    pub fn set_label_color(&mut self, color: u8) {
        let f = (self.finder_flags() & !flags::COLOR_MASK) | ((u16::from(color) & 7) << 1);
        self.set_finder_flags(f);
    }

    /// Extended Finder flags; see [`extended_flags`].
    pub fn extended_flags(&self) -> u16 {
        self.u16_at(24)
    }

    /// Replace the extended Finder flags.
    pub fn set_extended_flags(&mut self, v: u16) {
        self.set_u16_at(24, v)
    }

    /// `fdPutAway` / `frPutAway`: CNID of the folder an item on the
    /// desktop (or in the Trash) was put away from.
    pub fn put_away_folder_id(&self) -> u32 {
        self.u32_at(28)
    }

    /// Set the put-away folder CNID.
    pub fn set_put_away_folder_id(&mut self, v: u32) {
        self.set_u32_at(28, v)
    }

    // -- file view (FileInfo + ExtendedFileInfo) ---------------------

    /// File type OSType (`fdType`), e.g. `*b"APPL"`.
    pub fn file_type(&self) -> [u8; 4] {
        self.bytes[0..4].try_into().unwrap()
    }

    /// Set the file type OSType.
    pub fn set_file_type(&mut self, t: [u8; 4]) {
        self.bytes[0..4].copy_from_slice(&t);
    }

    /// Creator OSType (`fdCreator`).
    pub fn creator(&self) -> [u8; 4] {
        self.bytes[4..8].try_into().unwrap()
    }

    /// Set the creator OSType.
    pub fn set_creator(&mut self, c: [u8; 4]) {
        self.bytes[4..8].copy_from_slice(&c);
    }

    // -- folder view (FolderInfo + ExtendedFolderInfo) ---------------

    /// Folder window rectangle `(top, left, bottom, right)` (`frRect`).
    pub fn window_rect(&self) -> (i16, i16, i16, i16) {
        (
            self.i16_at(0),
            self.i16_at(2),
            self.i16_at(4),
            self.i16_at(6),
        )
    }

    /// Set the folder window rectangle `(top, left, bottom, right)`.
    pub fn set_window_rect(&mut self, top: i16, left: i16, bottom: i16, right: i16) {
        self.set_i16_at(0, top);
        self.set_i16_at(2, left);
        self.set_i16_at(4, bottom);
        self.set_i16_at(6, right);
    }

    /// Folder view (`frView`).
    pub fn folder_view(&self) -> u16 {
        self.u16_at(14)
    }

    /// Set the folder view.
    pub fn set_folder_view(&mut self, v: u16) {
        self.set_u16_at(14, v)
    }

    /// Folder scroll position `(v, h)` (`frScroll`).
    pub fn scroll_position(&self) -> (i16, i16) {
        (self.i16_at(16), self.i16_at(18))
    }

    /// Set the folder scroll position `(v, h)`.
    pub fn set_scroll_position(&mut self, v: i16, h: i16) {
        self.set_i16_at(16, v);
        self.set_i16_at(18, h);
    }
}

impl From<[u8; 32]> for FinderInfo {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<FinderInfo> for [u8; 32] {
    fn from(f: FinderInfo) -> Self {
        f.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accessors_hit_the_documented_offsets() {
        let mut f = FinderInfo::default();
        f.set_file_type(*b"APPL");
        f.set_creator(*b"????");
        f.set_finder_flags(flags::HAS_CUSTOM_ICON | flags::HAS_BUNDLE);
        f.set_location(-1, 300);
        f.set_extended_flags(extended_flags::ARE_INVALID);
        f.set_put_away_folder_id(0x1234_5678);
        let b = f.to_bytes();
        assert_eq!(&b[0..8], b"APPL????");
        assert_eq!(&b[8..10], &[0x24, 0x00]);
        assert_eq!(&b[10..14], &[0xFF, 0xFF, 0x01, 0x2C]);
        assert_eq!(&b[24..26], &[0x80, 0x00]);
        assert_eq!(&b[28..32], &[0x12, 0x34, 0x56, 0x78]);
        f.set_label_color(5);
        assert_eq!(f.label_color(), 5);
        assert_eq!(
            f.finder_flags() & flags::HAS_CUSTOM_ICON,
            flags::HAS_CUSTOM_ICON
        );
        assert_eq!(FinderInfo::from_slice(&b).unwrap().file_type(), *b"APPL");
        assert!(FinderInfo::from_slice(&b[..31]).is_err());
    }

    #[test]
    fn folder_view_overlays() {
        let mut f = FinderInfo::default();
        f.set_window_rect(10, 20, 410, 620);
        f.set_scroll_position(3, 4);
        assert_eq!(f.window_rect(), (10, 20, 410, 620));
        assert_eq!(f.scroll_position(), (3, 4));
        assert_eq!(&f.to_bytes()[0..2], &[0, 10]);
    }
}
