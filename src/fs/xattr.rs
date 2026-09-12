//! The extended-attribute pair every backend exchanges.
//!
//! An [`Xattr`] is the format-neutral `(name, value)` that tar's PAX
//! headers, SquashFS, APFS, ext and the FUSE adapter all pass around; each
//! backend's on-disk encoding lives with that backend (see
//! `fs::ext::xattr` for ext's block layout).

use alloc::string::String;
use alloc::vec::Vec;

/// One extended attribute: the full name including its namespace prefix
/// (`"user.something"`, `"security.selinux"`, …) and the raw value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xattr {
    /// Full attribute name including the namespace prefix
    /// (e.g. `"user.something"`, `"security.selinux"`).
    pub name: String,
    /// The attribute's value, as raw bytes.
    pub value: Vec<u8>,
}

impl Xattr {
    /// An attribute `name` carrying `value`.
    pub fn new(name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}
