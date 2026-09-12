//! Paths inside an image: [`Path`] and [`PathBuf`].
//!
//! The filesystem layer names entries with `Path`s. With the `std`
//! feature (the default) these are `std::path::Path` and
//! `std::path::PathBuf` themselves, re-exported, so a hosted consumer
//! passes the paths it already has.
//!
//! Without `std` the crate is `#![no_std]`, and this module supplies a
//! small `Path` / `PathBuf` pair of its own with the same method names and
//! the same component rules as `std`'s Unix flavour: `/` separates,
//! repeated separators and `.` collapse, comparison is by components.
//! Paths inside an image are always this shape, whatever the host, so the
//! filesystem code is written once against this module and compiles
//! unchanged in either configuration.

#[cfg(feature = "std")]
pub use std::path::{Path, PathBuf};

#[cfg(not(feature = "std"))]
pub use nostd::{Component, Components, Display, OsStr, Path, PathBuf};

/// The `no_std` stand-in for `std::path` (Unix rules).
#[cfg(not(feature = "std"))]
mod nostd {
    use alloc::borrow::{Cow, ToOwned};
    use alloc::string::String;
    use core::fmt;
    use core::hash::{Hash, Hasher};

    /// A borrowed string that plays the role `std::ffi::OsStr` plays in
    /// `std::path` — the type of a path component. Always valid UTF-8 here.
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[repr(transparent)]
    pub struct OsStr {
        inner: str,
    }

    impl OsStr {
        /// View `s` as an [`OsStr`].
        pub fn new<S: AsRef<str> + ?Sized>(s: &S) -> &OsStr {
            let s: &str = s.as_ref();
            // SAFETY: `OsStr` is `#[repr(transparent)]` over `str`, so the
            // two references have the same layout and validity.
            unsafe { &*(s as *const str as *const OsStr) }
        }

        /// The component as `&str`. Always `Some` here (see the type docs).
        pub fn to_str(&self) -> Option<&str> {
            Some(&self.inner)
        }

        /// The component as a string, lossily (never actually lossy here).
        pub fn to_string_lossy(&self) -> Cow<'_, str> {
            Cow::Borrowed(&self.inner)
        }

        /// Length in bytes.
        pub fn len(&self) -> usize {
            self.inner.len()
        }

        /// Whether the component is empty.
        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }
    }

    impl fmt::Debug for OsStr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(&self.inner, f)
        }
    }

    impl AsRef<OsStr> for str {
        fn as_ref(&self) -> &OsStr {
            OsStr::new(self)
        }
    }

    impl AsRef<OsStr> for String {
        fn as_ref(&self) -> &OsStr {
            OsStr::new(self.as_str())
        }
    }

    impl AsRef<Path> for OsStr {
        fn as_ref(&self) -> &Path {
            Path::new(&self.inner)
        }
    }

    impl PartialEq<str> for OsStr {
        fn eq(&self, other: &str) -> bool {
            &self.inner == other
        }
    }

    /// One piece of a path, as yielded by [`Path::components`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Component<'a> {
        /// The leading `/`.
        RootDir,
        /// A leading `.`.
        CurDir,
        /// A `..`.
        ParentDir,
        /// A plain name.
        Normal(&'a OsStr),
    }

    impl<'a> Component<'a> {
        /// The component's text (`/`, `.`, `..`, or the name).
        pub fn as_os_str(self) -> &'a OsStr {
            match self {
                Component::RootDir => OsStr::new("/"),
                Component::CurDir => OsStr::new("."),
                Component::ParentDir => OsStr::new(".."),
                Component::Normal(s) => s,
            }
        }
    }

    impl AsRef<Path> for Component<'_> {
        fn as_ref(&self) -> &Path {
            self.as_os_str().as_ref()
        }
    }

    /// Iterator over a path's [`Component`]s (see [`Path::components`]).
    #[derive(Debug, Clone)]
    pub struct Components<'a> {
        rest: &'a str,
        root_pending: bool,
        at_start: bool,
    }

    impl<'a> Iterator for Components<'a> {
        type Item = Component<'a>;

        fn next(&mut self) -> Option<Component<'a>> {
            if self.root_pending {
                self.root_pending = false;
                self.at_start = false;
                return Some(Component::RootDir);
            }
            loop {
                self.rest = self.rest.trim_start_matches('/');
                if self.rest.is_empty() {
                    return None;
                }
                let (seg, tail) = match self.rest.find('/') {
                    Some(i) => (&self.rest[..i], &self.rest[i..]),
                    None => (self.rest, ""),
                };
                self.rest = tail;
                let at_start = core::mem::replace(&mut self.at_start, false);
                return match seg {
                    "." if at_start => Some(Component::CurDir),
                    "." => continue,
                    ".." => Some(Component::ParentDir),
                    s => Some(Component::Normal(OsStr::new(s))),
                };
            }
        }
    }

    /// A borrowed path (see the [module docs](self)).
    #[repr(transparent)]
    pub struct Path {
        inner: str,
    }

    /// Helper returned by [`Path::display`].
    pub struct Display<'a> {
        path: &'a Path,
    }

    impl fmt::Display for Display<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.path.inner)
        }
    }

    impl fmt::Debug for Display<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(&self.path.inner, f)
        }
    }

    impl Path {
        /// View `s` as a [`Path`]. Free: no allocation, no validation.
        pub fn new<S: AsRef<str> + ?Sized>(s: &S) -> &Path {
            let s: &str = s.as_ref();
            // SAFETY: `Path` is `#[repr(transparent)]` over `str`, so the two
            // references have the same layout and validity.
            unsafe { &*(s as *const str as *const Path) }
        }

        /// The whole path as an [`OsStr`].
        pub fn as_os_str(&self) -> &OsStr {
            OsStr::new(&self.inner)
        }

        /// The whole path as `&str`. Always `Some` here.
        pub fn to_str(&self) -> Option<&str> {
            Some(&self.inner)
        }

        /// The whole path as a string, lossily (never actually lossy here).
        pub fn to_string_lossy(&self) -> Cow<'_, str> {
            Cow::Borrowed(&self.inner)
        }

        /// An owned copy.
        pub fn to_path_buf(&self) -> PathBuf {
            PathBuf {
                inner: self.inner.to_owned(),
            }
        }

        /// Whether the path starts with `/`.
        pub fn is_absolute(&self) -> bool {
            self.has_root()
        }

        /// Whether the path starts with `/`.
        pub fn has_root(&self) -> bool {
            self.inner.starts_with('/')
        }

        /// Whether the path is relative (does not start with `/`).
        pub fn is_relative(&self) -> bool {
            !self.has_root()
        }

        /// The path's components, normalised: `/` separators, repeated
        /// separators collapsed, `.` dropped except when leading.
        pub fn components(&self) -> Components<'_> {
            Components {
                rest: &self.inner,
                root_pending: self.has_root(),
                at_start: true,
            }
        }

        /// The components' text, in order (`/` for the root).
        pub fn iter(&self) -> impl Iterator<Item = &OsStr> + '_ {
            self.components().map(Component::as_os_str)
        }

        /// The path without its final component: `None` for `/` and for
        /// the empty path, `Some("")` for a bare name.
        pub fn parent(&self) -> Option<&Path> {
            let mut last: Option<(usize, Component<'_>)> = None;
            let mut rest = &self.inner[..];
            let mut offset = 0usize;
            let mut comps = self.components();
            // Walk the components while tracking where each one starts in
            // the source string.
            if comps.root_pending {
                comps.root_pending = false;
                comps.at_start = false;
                last = Some((0, Component::RootDir));
            }
            loop {
                let trimmed = rest.trim_start_matches('/');
                offset += rest.len() - trimmed.len();
                rest = trimmed;
                if rest.is_empty() {
                    break;
                }
                let seg_len = rest.find('/').unwrap_or(rest.len());
                let seg = &rest[..seg_len];
                let at_start = core::mem::replace(&mut comps.at_start, false);
                let comp = match seg {
                    "." if at_start => Some(Component::CurDir),
                    "." => None,
                    ".." => Some(Component::ParentDir),
                    s => Some(Component::Normal(OsStr::new(s))),
                };
                if let Some(c) = comp {
                    last = Some((offset, c));
                }
                offset += seg_len;
                rest = &rest[seg_len..];
            }
            match last {
                None | Some((_, Component::RootDir)) => None,
                Some((start, _)) => {
                    let mut end = start;
                    while end > 0 && self.inner.as_bytes()[end - 1] == b'/' {
                        end -= 1;
                    }
                    if end == 0 && self.has_root() {
                        end = 1;
                    }
                    Some(Path::new(&self.inner[..end]))
                }
            }
        }

        /// The final component, if it is a plain name.
        pub fn file_name(&self) -> Option<&OsStr> {
            match self.components().last()? {
                Component::Normal(s) => Some(s),
                _ => None,
            }
        }

        /// `file_name` without its last `.`-suffix.
        pub fn file_stem(&self) -> Option<&OsStr> {
            let name = self.file_name()?.to_str()?;
            Some(OsStr::new(match name.rfind('.') {
                Some(0) | None => name,
                Some(i) => &name[..i],
            }))
        }

        /// `file_name`'s last `.`-suffix, without the dot.
        pub fn extension(&self) -> Option<&OsStr> {
            let name = self.file_name()?.to_str()?;
            match name.rfind('.') {
                Some(0) | None => None,
                Some(i) => Some(OsStr::new(&name[i + 1..])),
            }
        }

        /// Whether `base` is a component-wise prefix of this path.
        pub fn starts_with<P: AsRef<Path>>(&self, base: P) -> bool {
            let mut mine = self.components();
            for b in base.as_ref().components() {
                if mine.next() != Some(b) {
                    return false;
                }
            }
            true
        }

        /// This path with the component-wise prefix `base` removed.
        pub fn strip_prefix<P: AsRef<Path>>(&self, base: P) -> Result<&Path, StripPrefixError> {
            let base = base.as_ref();
            if !self.starts_with(base) {
                return Err(StripPrefixError(()));
            }
            let n = base.components().count();
            let mut rest = &self.inner[..];
            let mut comps = self.components();
            // Skip `n` components in the raw text.
            for _ in 0..n {
                if comps.root_pending {
                    comps.root_pending = false;
                    comps.at_start = false;
                    rest = &rest[1..];
                    continue;
                }
                loop {
                    rest = rest.trim_start_matches('/');
                    let seg_len = rest.find('/').unwrap_or(rest.len());
                    let seg = &rest[..seg_len];
                    let at_start = core::mem::replace(&mut comps.at_start, false);
                    rest = &rest[seg_len..];
                    if seg == "." && !at_start {
                        continue;
                    }
                    break;
                }
            }
            // Only trim the separator after a consumed component; with an
            // empty prefix the path (root included) comes back unchanged,
            // matching std.
            if n == 0 {
                return Ok(self);
            }
            Ok(Path::new(rest.trim_start_matches('/')))
        }

        /// This path with `p` appended (or `p` itself if it is absolute).
        pub fn join<P: AsRef<Path>>(&self, p: P) -> PathBuf {
            let mut out = self.to_path_buf();
            out.push(p);
            out
        }

        /// A `Display` helper (paths are always printable here).
        pub fn display(&self) -> Display<'_> {
            Display { path: self }
        }
    }

    /// Error from [`Path::strip_prefix`]: `base` was not a prefix.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StripPrefixError(());

    impl fmt::Display for StripPrefixError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("prefix not found")
        }
    }

    impl core::error::Error for StripPrefixError {}

    impl fmt::Debug for Path {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(&self.inner, f)
        }
    }

    impl PartialEq for Path {
        fn eq(&self, other: &Path) -> bool {
            self.components().eq(other.components())
        }
    }

    impl Eq for Path {}

    impl PartialOrd for Path {
        fn partial_cmp(&self, other: &Path) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for Path {
        fn cmp(&self, other: &Path) -> core::cmp::Ordering {
            self.components().cmp(other.components())
        }
    }

    impl Hash for Path {
        fn hash<H: Hasher>(&self, state: &mut H) {
            for c in self.components() {
                c.hash(state);
            }
        }
    }

    impl AsRef<Path> for Path {
        fn as_ref(&self) -> &Path {
            self
        }
    }

    impl AsRef<Path> for str {
        fn as_ref(&self) -> &Path {
            Path::new(self)
        }
    }

    impl AsRef<Path> for String {
        fn as_ref(&self) -> &Path {
            Path::new(self.as_str())
        }
    }

    impl AsRef<Path> for Cow<'_, str> {
        fn as_ref(&self) -> &Path {
            Path::new(&**self)
        }
    }

    impl ToOwned for Path {
        type Owned = PathBuf;
        fn to_owned(&self) -> PathBuf {
            self.to_path_buf()
        }
    }

    impl<'a> IntoIterator for &'a Path {
        type Item = &'a OsStr;
        type IntoIter = core::iter::Map<Components<'a>, fn(Component<'a>) -> &'a OsStr>;
        fn into_iter(self) -> Self::IntoIter {
            self.components().map(Component::as_os_str)
        }
    }

    /// An owned path (see the [module docs](self)).
    #[derive(Clone, Default)]
    pub struct PathBuf {
        inner: String,
    }

    impl PathBuf {
        /// An empty path.
        pub const fn new() -> Self {
            Self {
                inner: String::new(),
            }
        }

        /// Borrow as a [`Path`].
        pub fn as_path(&self) -> &Path {
            Path::new(self.inner.as_str())
        }

        /// Append `p`, inserting a `/` if needed; an absolute `p` replaces
        /// the whole path.
        pub fn push<P: AsRef<Path>>(&mut self, p: P) {
            let p = &p.as_ref().inner;
            if p.starts_with('/') {
                self.inner.clear();
            } else if !self.inner.is_empty() && !self.inner.ends_with('/') {
                self.inner.push('/');
            }
            self.inner.push_str(p);
        }

        /// Drop the final component; `false` if there was none to drop.
        pub fn pop(&mut self) -> bool {
            match self.as_path().parent().map(|p| p.inner.len()) {
                Some(len) => {
                    self.inner.truncate(len);
                    true
                }
                None => false,
            }
        }

        /// Replace the final component with `name` (or append it if the
        /// path has no file name).
        pub fn set_file_name<S: AsRef<str>>(&mut self, name: S) {
            if self.as_path().file_name().is_some() {
                self.pop();
            }
            self.push(name.as_ref());
        }

        /// Replace (or add) the extension of the final component.
        pub fn set_extension<S: AsRef<str>>(&mut self, ext: S) -> bool {
            let Some(stem) = self.as_path().file_stem() else {
                return false;
            };
            let mut name = String::from(stem.to_str().unwrap_or(""));
            let ext = ext.as_ref();
            if !ext.is_empty() {
                name.push('.');
                name.push_str(ext);
            }
            self.set_file_name(name);
            true
        }

        /// The path's text.
        pub fn into_string(self) -> String {
            self.inner
        }
    }

    impl core::ops::Deref for PathBuf {
        type Target = Path;
        fn deref(&self) -> &Path {
            self.as_path()
        }
    }

    impl core::borrow::Borrow<Path> for PathBuf {
        fn borrow(&self) -> &Path {
            self.as_path()
        }
    }

    impl AsRef<Path> for PathBuf {
        fn as_ref(&self) -> &Path {
            self.as_path()
        }
    }

    impl AsRef<OsStr> for PathBuf {
        fn as_ref(&self) -> &OsStr {
            OsStr::new(self.inner.as_str())
        }
    }

    impl fmt::Debug for PathBuf {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Debug::fmt(&self.inner, f)
        }
    }

    impl PartialEq for PathBuf {
        fn eq(&self, other: &PathBuf) -> bool {
            self.as_path() == other.as_path()
        }
    }

    impl Eq for PathBuf {}

    impl PartialEq<Path> for PathBuf {
        fn eq(&self, other: &Path) -> bool {
            self.as_path() == other
        }
    }

    impl PartialEq<PathBuf> for Path {
        fn eq(&self, other: &PathBuf) -> bool {
            self == other.as_path()
        }
    }

    impl PartialEq<&Path> for PathBuf {
        fn eq(&self, other: &&Path) -> bool {
            self.as_path() == *other
        }
    }

    impl PartialEq<PathBuf> for &Path {
        fn eq(&self, other: &PathBuf) -> bool {
            *self == other.as_path()
        }
    }

    impl PartialOrd for PathBuf {
        fn partial_cmp(&self, other: &PathBuf) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for PathBuf {
        fn cmp(&self, other: &PathBuf) -> core::cmp::Ordering {
            self.as_path().cmp(other.as_path())
        }
    }

    impl Hash for PathBuf {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.as_path().hash(state);
        }
    }

    impl From<String> for PathBuf {
        fn from(s: String) -> Self {
            Self { inner: s }
        }
    }

    impl From<&str> for PathBuf {
        fn from(s: &str) -> Self {
            Self {
                inner: s.to_owned(),
            }
        }
    }

    impl From<&String> for PathBuf {
        fn from(s: &String) -> Self {
            Self { inner: s.clone() }
        }
    }

    impl From<&Path> for PathBuf {
        fn from(p: &Path) -> Self {
            p.to_path_buf()
        }
    }

    impl From<Cow<'_, str>> for PathBuf {
        fn from(s: Cow<'_, str>) -> Self {
            Self {
                inner: s.into_owned(),
            }
        }
    }

    impl From<PathBuf> for String {
        fn from(p: PathBuf) -> Self {
            p.inner
        }
    }

    impl core::str::FromStr for PathBuf {
        type Err = core::convert::Infallible;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(Self::from(s))
        }
    }

    impl<P: AsRef<Path>> Extend<P> for PathBuf {
        fn extend<I: IntoIterator<Item = P>>(&mut self, iter: I) {
            for p in iter {
                self.push(p);
            }
        }
    }

    impl<P: AsRef<Path>> FromIterator<P> for PathBuf {
        fn from_iter<I: IntoIterator<Item = P>>(iter: I) -> Self {
            let mut out = PathBuf::new();
            out.extend(iter);
            out
        }
    }
}

#[cfg(all(test, not(feature = "std")))]
mod tests {
    use super::*;

    #[test]
    fn components_normalise_like_std_unix() {
        let names: alloc::vec::Vec<&str> = Path::new("/a//./b/../c/")
            .iter()
            .map(|c| c.to_str().unwrap())
            .collect();
        assert_eq!(names, ["/", "a", "b", "..", "c"]);
        let names: alloc::vec::Vec<&str> = Path::new("./x/./y")
            .iter()
            .map(|c| c.to_str().unwrap())
            .collect();
        assert_eq!(names, [".", "x", "y"]);
        assert_eq!(Path::new("/a/b/"), Path::new("/a/b"));
        assert_ne!(Path::new("/a/b"), Path::new("a/b"));
    }

    #[test]
    fn parent_and_file_name() {
        assert_eq!(Path::new("/").parent(), None);
        assert_eq!(Path::new("").parent(), None);
        assert_eq!(Path::new("/a").parent(), Some(Path::new("/")));
        assert_eq!(Path::new("/a/b").parent(), Some(Path::new("/a")));
        assert_eq!(Path::new("a").parent(), Some(Path::new("")));
        assert_eq!(Path::new("/a/b/").parent(), Some(Path::new("/a")));
        assert_eq!(
            Path::new("/a/b.txt").file_name().and_then(|n| n.to_str()),
            Some("b.txt")
        );
        assert_eq!(Path::new("/").file_name(), None);
        assert_eq!(Path::new("/a/..").file_name(), None);
        assert_eq!(
            Path::new("/a/b.tar.gz")
                .extension()
                .and_then(|e| e.to_str()),
            Some("gz")
        );
        assert_eq!(
            Path::new("/a/b.tar.gz")
                .file_stem()
                .and_then(|e| e.to_str()),
            Some("b.tar")
        );
    }

    #[test]
    fn join_push_pop() {
        let mut p = PathBuf::from("/a");
        p.push("b");
        assert_eq!(p.as_path(), Path::new("/a/b"));
        p.push("/root");
        assert_eq!(p.as_path(), Path::new("/root"));
        assert!(p.pop());
        assert_eq!(p.as_path(), Path::new("/"));
        assert!(!p.pop());
        assert_eq!(Path::new("/x").join("y/z"), PathBuf::from("/x/y/z"));
        assert_eq!(Path::new("").join("y"), PathBuf::from("y"));
    }

    #[test]
    fn prefix_ops() {
        assert!(Path::new("/a/b/c").starts_with("/a/b"));
        assert!(!Path::new("/a/bc").starts_with("/a/b"));
        assert_eq!(
            Path::new("/a/b/c").strip_prefix("/a").unwrap(),
            Path::new("b/c")
        );
        assert!(Path::new("/a").strip_prefix("/b").is_err());
    }
}
