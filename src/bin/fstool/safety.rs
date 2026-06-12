//! Defensive helpers for handling image-supplied names on the host side.
//!
//! On-image directory-entry names, symlink targets and xattr names are
//! attacker-controlled: a malicious image can carry an entry literally named
//! `../../etc/cron.d/x`, `/etc/passwd`, or one stuffed with terminal escape
//! sequences. Two distinct hazards follow, handled here:
//!
//! * [`safe_component`] guards the *path-building* sinks (`get`, the recursive
//!   walks): a name used to build a host path must be exactly one normal path
//!   component, never `.`/`..`, never containing a separator or NUL.
//! * [`sanitize_name`] guards the *display* sinks: any image-supplied string
//!   printed to a terminal has its C0/C1/DEL control bytes rendered as visible
//!   `\xNN` escapes so it cannot rewrite the user's screen.

/// True iff `name` is exactly one ordinary path component — i.e. safe to
/// `Path::join` onto a host (or image) base without escaping it.
///
/// Rejects the empty string, `.`, `..`, anything containing a `/` or the
/// platform separator, anything containing a NUL, and any path that resolves
/// to more than a single [`std::path::Component::Normal`] (which also catches
/// absolute paths, Windows drive prefixes, and `..`).
pub fn safe_component(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return false;
    }
    if name.contains('\0') || name.contains('/') {
        return false;
    }
    #[cfg(windows)]
    if name.contains('\\') {
        return false;
    }
    let mut comps = std::path::Path::new(name).components();
    matches!(
        (comps.next(), comps.next()),
        (Some(std::path::Component::Normal(_)), None)
    )
}

/// Render an image-supplied string for display, escaping control characters
/// that could otherwise inject terminal escape sequences. Bytes below `0x20`,
/// the DEL byte `0x7f`, and the C1 range `0x80..=0x9f` (when they appear as
/// such in the UTF-8 stream) are replaced with a visible `\xNN` escape; a
/// literal backslash is doubled so the escaping is unambiguous. All other
/// characters — including ordinary printable Unicode — pass through unchanged,
/// so the mapping is a no-op for benign names.
pub fn sanitize_name(s: &str) -> String {
    // Fast path: the overwhelmingly common case is a name with nothing to
    // escape, so scan first and only allocate when we must.
    let needs = s
        .bytes()
        .any(|b| b < 0x20 || b == 0x7f || (0x80..=0x9f).contains(&b) || b == b'\\');
    if !needs {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f || (0x80..=0x9f).contains(&(c as u32)) => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_component_accepts_normal_names() {
        for n in ["file", "a.txt", "weird name", "A:ROSE Includes", "résumé"] {
            assert!(safe_component(n), "{n:?} should be a safe component");
        }
    }

    #[test]
    fn safe_component_rejects_traversal_and_separators() {
        for n in [
            "",
            ".",
            "..",
            "/",
            "/etc/passwd",
            "../x",
            "a/b",
            "a/../b",
            "with\0nul",
            "./x",
        ] {
            assert!(!safe_component(n), "{n:?} should be rejected");
        }
    }

    #[test]
    fn sanitize_passes_benign_names() {
        for n in ["file.txt", "A:ROSE Includes", "café", "a b c"] {
            assert_eq!(sanitize_name(n), n, "{n:?} should pass through");
        }
    }

    #[test]
    fn sanitize_escapes_control_bytes() {
        // ESC, bell, newline, DEL, and a literal backslash.
        assert_eq!(sanitize_name("a\x1b[31mb"), "a\\x1b[31mb");
        assert_eq!(sanitize_name("x\x07y"), "x\\x07y");
        assert_eq!(sanitize_name("a\nb"), "a\\x0ab");
        assert_eq!(sanitize_name("a\x7fb"), "a\\x7fb");
        assert_eq!(sanitize_name("a\\b"), "a\\\\b");
    }
}
