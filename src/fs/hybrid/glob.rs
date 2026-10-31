//! Minimal shell-style globs for the per-view `hide` / `only` filters.
//!
//! `*` matches any run of characters except `/`, `?` one such character,
//! `[abc]` / `[a-z]` / `[!x]` a character class, and `\` escapes the next
//! character. A pattern without a `/` is matched against an entry's name
//! (as `hdiutil makehybrid -hide-hfs` does); one with a `/` against its
//! whole path below the root, without the leading `/`.

/// A compiled glob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Glob {
    text: String,
    pat: Vec<char>,
    path: bool,
}

impl Glob {
    pub(crate) fn new(text: &str) -> Self {
        let trimmed = text.trim_start_matches('/');
        Self {
            text: text.to_string(),
            pat: trimmed.chars().collect(),
            path: trimmed.contains('/'),
        }
    }

    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// Does the entry at `path` (relative to the root, no leading `/`)
    /// named `name` match?
    pub(crate) fn matches(&self, path: &str, name: &str) -> bool {
        let subject: Vec<char> = if self.path {
            path.trim_start_matches('/').chars().collect()
        } else {
            name.chars().collect()
        };
        matches(&self.pat, &subject)
    }
}

fn matches(p: &[char], s: &[char]) -> bool {
    // Iterative matcher with single-star backtracking.
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() {
            match p[pi] {
                '*' => {
                    star = Some((pi, si));
                    pi += 1;
                    continue;
                }
                '?' if s[si] != '/' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                '[' => {
                    if let Some((ok, next)) = class(&p[pi..], s[si])
                        && ok
                    {
                        pi += next;
                        si += 1;
                        continue;
                    }
                }
                '\\' if pi + 1 < p.len() => {
                    if p[pi + 1] == s[si] {
                        pi += 2;
                        si += 1;
                        continue;
                    }
                }
                c if c == s[si] && c != '?' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        }
        match star {
            Some((sp, ss)) if s[ss] != '/' => {
                star = Some((sp, ss + 1));
                pi = sp + 1;
                si = ss + 1;
            }
            _ => return false,
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Match `c` against the class starting at `p[0] == '['`. Returns
/// (matched, pattern chars consumed), or `None` for an unterminated
/// class (then `[` is literal).
fn class(p: &[char], c: char) -> Option<(bool, usize)> {
    let mut i = 1;
    let negate = matches!(p.get(i), Some('!' | '^'));
    if negate {
        i += 1;
    }
    let mut hit = false;
    let mut first = true;
    while i < p.len() {
        if p[i] == ']' && !first {
            return Some((hit != negate, i + 1));
        }
        first = false;
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            if p[i] <= c && c <= p[i + 2] {
                hit = true;
            }
            i += 3;
        } else {
            if p[i] == c {
                hit = true;
            }
            i += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::Glob;

    #[test]
    fn names_and_paths() {
        let g = Glob::new("*.txt");
        assert!(g.matches("a/b/readme.txt", "readme.txt"));
        assert!(!g.matches("a/readme.md", "readme.md"));
        let g = Glob::new("/sub/*.bin");
        assert!(g.matches("sub/x.bin", "x.bin"));
        assert!(!g.matches("sub/deeper/x.bin", "x.bin"));
        assert!(Glob::new(".DS_Store").matches("x/.DS_Store", ".DS_Store"));
        assert!(Glob::new("file?.[ch]").matches("file1.c", "file1.c"));
        assert!(!Glob::new("file?.[!ch]").matches("file1.c", "file1.c"));
        assert!(Glob::new("[a-c]*").matches("b", "b"));
        assert!(Glob::new("*").matches("anything", "anything"));
        assert!(Glob::new("a\\*").matches("a*", "a*"));
        assert!(!Glob::new("a\\*").matches("ab", "ab"));
    }
}
