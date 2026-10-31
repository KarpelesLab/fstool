//! What a view could not represent exactly — reported, never silent.

use std::fmt;

use super::view::ViewId;

/// Why an entry is absent from a view.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OmitReason {
    /// Hidden on request: a `hide` glob of this view, or an `only` glob
    /// of another view, matched it (or a parent directory).
    Hidden {
        /// The glob that matched.
        pattern: String,
    },
    /// The view has no way to represent this kind of entry (a symlink in
    /// plain ISO 9660 or Joliet, a device node in Joliet, …).
    Unrepresentable {
        /// The kind of entry: `"symlink"`, `"device"`, `"fifo"`, `"socket"`.
        kind: &'static str,
    },
    /// The file is larger than the view can describe (4 GiB and more
    /// below ISO 9660 interchange level 3).
    TooLarge {
        /// File size in bytes.
        size: u64,
        /// The largest size the view can record.
        limit: u64,
    },
    /// The entry's parent is absent from the view, so it is too.
    ParentAbsent,
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReportKind {
    /// The name was changed to fit the view's character set or to avoid
    /// a collision (`to` is the name a reader of that view sees).
    NameMapped {
        /// The source name.
        from: String,
        /// The name in this view.
        to: String,
    },
    /// The name was shortened to the view's length limit (and possibly
    /// mapped as well).
    NameTruncated {
        /// The source name.
        from: String,
        /// The name in this view.
        to: String,
    },
    /// The entry is not in this view.
    Omitted(OmitReason),
    /// A piece of metadata the source carries has no home in this view
    /// (`what` says which: `"permissions"`, `"ownership"`, `"xattrs"`,
    /// `"hard link"` — the link becomes an independent copy of the same
    /// payload — …). The entry itself is present.
    MetadataDropped {
        /// What is dropped.
        what: &'static str,
    },
    /// The directory is deeper than ECMA-119's eight levels. It is
    /// recorded as is (every common reader accepts it); strict readers
    /// may refuse it.
    DepthExceeded {
        /// The entry's depth.
        depth: usize,
    },
    /// A volume label was changed to fit the view.
    LabelMapped {
        /// The requested label.
        from: String,
        /// The label written.
        to: String,
    },
    /// Anything else worth knowing about the view.
    Note(String),
}

/// One item of a [`HybridReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReportItem {
    /// The view concerned.
    pub view: ViewId,
    /// Tree path of the entry (`"/"` for volume-wide items).
    pub path: String,
    /// What happened.
    pub kind: ReportKind,
}

/// Everything the planner had to change or leave out, per view. Entries
/// hidden on request are listed too, so the report fully accounts for
/// how each view's tree differs from the source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HybridReport {
    items: Vec<ReportItem>,
}

impl HybridReport {
    /// Record an item.
    pub fn push(&mut self, view: ViewId, path: impl Into<String>, kind: ReportKind) {
        self.items.push(ReportItem {
            view,
            path: path.into(),
            kind,
        });
    }

    /// All items, in the order found.
    pub fn items(&self) -> &[ReportItem] {
        &self.items
    }

    /// Items about one view.
    pub fn for_view(&self, view: ViewId) -> impl Iterator<Item = &ReportItem> {
        self.items.iter().filter(move |i| i.view == view)
    }

    /// True when every view represents the source exactly.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Items other than [`OmitReason::Hidden`] — what the caller did not
    /// explicitly ask for.
    pub fn unrequested(&self) -> impl Iterator<Item = &ReportItem> {
        self.items.iter().filter(|i| {
            !matches!(
                i.kind,
                ReportKind::Omitted(OmitReason::Hidden { .. } | OmitReason::ParentAbsent)
            )
        })
    }
}

impl fmt::Display for ReportItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}: ", self.view, self.path)?;
        match &self.kind {
            ReportKind::NameMapped { to, .. } => write!(f, "name mapped to {to:?}"),
            ReportKind::NameTruncated { to, .. } => write!(f, "name truncated to {to:?}"),
            ReportKind::Omitted(OmitReason::Hidden { pattern }) => {
                write!(f, "hidden (matches {pattern:?})")
            }
            ReportKind::Omitted(OmitReason::Unrepresentable { kind }) => {
                write!(f, "omitted: a {kind} cannot be represented")
            }
            ReportKind::Omitted(OmitReason::TooLarge { size, limit }) => {
                write!(
                    f,
                    "omitted: {size} bytes exceeds the view's limit of {limit}"
                )
            }
            ReportKind::Omitted(OmitReason::ParentAbsent) => {
                write!(f, "omitted with its parent")
            }
            ReportKind::MetadataDropped { what } => write!(f, "{what} not representable"),
            ReportKind::DepthExceeded { depth } => {
                write!(f, "directory depth {depth} exceeds ECMA-119's 8 levels")
            }
            ReportKind::LabelMapped { from, to } => {
                write!(f, "volume label {from:?} written as {to:?}")
            }
            ReportKind::Note(n) => f.write_str(n),
        }
    }
}

impl fmt::Display for HybridReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in &self.items {
            writeln!(f, "{i}")?;
        }
        Ok(())
    }
}
