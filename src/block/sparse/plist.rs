//! A bounded reader for the one flat XML property list a sparsebundle
//! carries (`Info.plist`).
//!
//! The file is untrusted input, so this is deliberately small: it walks
//! the tags of a top-level `<plist><dict>…</dict></plist>`, records each
//! key with its scalar value (`<integer>`, `<string>`, `<true/>`, …), and
//! skips nested containers with a depth cap. A key seen twice is an
//! error — two answers to "how big is this image?" is not something to
//! guess between. Binary plists (`bplist00`) are refused; hdiutil writes
//! the XML form.

use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Range;

use crate::Result;

/// Largest `Info.plist` we read. Apple's is under 1 KiB.
pub const MAX_PLIST_BYTES: u64 = 64 * 1024;
/// Most keys we accept in the top-level dict.
const MAX_KEYS: usize = 256;
/// Deepest nesting of skipped containers.
const MAX_DEPTH: usize = 16;

/// One top-level `<key>` and its value.
#[derive(Debug, Clone)]
pub struct Entry {
    pub key: String,
    /// The value element's tag name (`integer`, `string`, `true`, `dict`, …).
    pub kind: String,
    /// The text between the value's open and close tags, entity-decoded.
    /// Empty for empty elements and containers.
    pub text: String,
    /// Byte range of the value's raw text in the source — what to replace
    /// to rewrite this value in place.
    pub text_span: Range<usize>,
}

fn bad(msg: &str) -> crate::Error {
    crate::Error::InvalidImage(alloc::format!("sparsebundle: Info.plist: {msg}"))
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum TagKind {
    Open,
    Close,
    Empty,
}

struct Tag<'a> {
    name: &'a str,
    kind: TagKind,
    /// Byte range of the whole `<…>`.
    span: Range<usize>,
}

/// The next element tag at or after `pos`, skipping the XML declaration,
/// DOCTYPE and comments. Text between tags is not returned.
fn next_tag(s: &str, mut pos: usize) -> Result<Option<Tag<'_>>> {
    loop {
        let Some(rel) = s[pos..].find('<') else {
            return Ok(None);
        };
        let start = pos + rel;
        let rest = &s[start..];
        if rest.starts_with("<!--") {
            let end = rest
                .find("-->")
                .ok_or_else(|| bad("unterminated comment"))?;
            pos = start + end + 3;
            continue;
        }
        if rest.starts_with("<?") || rest.starts_with("<!") {
            let end = rest
                .find('>')
                .ok_or_else(|| bad("unterminated declaration"))?;
            pos = start + end + 1;
            continue;
        }
        let end = start + rest.find('>').ok_or_else(|| bad("unterminated tag"))?;
        let mut inner = &s[start + 1..end];
        let kind = if let Some(n) = inner.strip_prefix('/') {
            inner = n;
            TagKind::Close
        } else if let Some(n) = inner.strip_suffix('/') {
            inner = n;
            TagKind::Empty
        } else {
            TagKind::Open
        };
        let name_end = inner
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(inner.len());
        let name = &inner[..name_end];
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            return Err(bad("malformed tag"));
        }
        return Ok(Some(Tag {
            name,
            kind,
            span: start..end + 1,
        }));
    }
}

fn decode_entities(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.into();
    }
    raw.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Parse the top-level dict of an XML plist.
pub fn parse_dict(src: &[u8]) -> Result<Vec<Entry>> {
    if src.len() as u64 > MAX_PLIST_BYTES {
        return Err(bad("larger than 64 KiB"));
    }
    if src.starts_with(b"bplist") {
        return Err(crate::Error::Unsupported(
            "sparsebundle: binary Info.plist is not supported".into(),
        ));
    }
    let s = core::str::from_utf8(src).map_err(|_| bad("not UTF-8"))?;
    let s = s.strip_prefix('\u{feff}').unwrap_or(s);

    let mut pos = 0;
    // <plist …>
    let t = next_tag(s, pos)?.ok_or_else(|| bad("empty"))?;
    if t.name != "plist" || t.kind != TagKind::Open {
        return Err(bad("root element is not <plist>"));
    }
    pos = t.span.end;
    let t = next_tag(s, pos)?.ok_or_else(|| bad("no <dict>"))?;
    if t.name != "dict" || t.kind != TagKind::Open {
        return Err(bad("root value is not a <dict>"));
    }
    pos = t.span.end;

    let mut out: Vec<Entry> = Vec::new();
    loop {
        let t = next_tag(s, pos)?.ok_or_else(|| bad("<dict> is not closed"))?;
        if t.name == "dict" && t.kind == TagKind::Close {
            break;
        }
        if t.name != "key" || t.kind != TagKind::Open {
            return Err(bad("expected <key>"));
        }
        let kstart = t.span.end;
        let kclose = next_tag(s, kstart)?.ok_or_else(|| bad("<key> is not closed"))?;
        if kclose.name != "key" || kclose.kind != TagKind::Close {
            return Err(bad("<key> holds an element"));
        }
        let key = decode_entities(s[kstart..kclose.span.start].trim());
        pos = kclose.span.end;

        let v = next_tag(s, pos)?.ok_or_else(|| bad("key without a value"))?;
        let kind: String = v.name.into();
        let (text, text_span, after) = match v.kind {
            TagKind::Empty => (String::new(), v.span.end..v.span.end, v.span.end),
            TagKind::Close => return Err(bad("key without a value")),
            TagKind::Open => {
                if matches!(v.name, "dict" | "array") {
                    let end = skip_container(s, v.span.end, v.name)?;
                    (String::new(), v.span.end..v.span.end, end)
                } else {
                    let c = next_tag(s, v.span.end)?.ok_or_else(|| bad("value is not closed"))?;
                    if c.name != v.name || c.kind != TagKind::Close {
                        return Err(bad("scalar value holds an element"));
                    }
                    let span = v.span.end..c.span.start;
                    (decode_entities(&s[span.clone()]), span, c.span.end)
                }
            }
        };
        pos = after;
        if out.iter().any(|e| e.key == key) {
            return Err(bad(&alloc::format!("duplicate key {key:?}")));
        }
        if out.len() >= MAX_KEYS {
            return Err(bad("too many keys"));
        }
        out.push(Entry {
            key,
            kind,
            text,
            text_span,
        });
    }
    Ok(out)
}

/// Skip to just past the close tag matching an already-consumed open
/// `<name>`, with nesting bounded by [`MAX_DEPTH`].
fn skip_container(s: &str, mut pos: usize, name: &str) -> Result<usize> {
    let mut stack: Vec<String> = alloc::vec![name.into()];
    while let Some(top) = stack.last().cloned() {
        let t = next_tag(s, pos)?.ok_or_else(|| bad("container is not closed"))?;
        pos = t.span.end;
        match t.kind {
            TagKind::Empty => {}
            TagKind::Open => {
                if stack.len() >= MAX_DEPTH {
                    return Err(bad("nested too deeply"));
                }
                stack.push(t.name.into());
            }
            TagKind::Close => {
                if t.name != top {
                    return Err(bad("mismatched close tag"));
                }
                stack.pop();
            }
        }
    }
    Ok(pos)
}

/// Look `key` up in parsed entries.
pub fn get<'a>(entries: &'a [Entry], key: &str) -> Option<&'a Entry> {
    entries.iter().find(|e| e.key == key)
}

/// `key` as a non-negative `<integer>`.
pub fn get_u64(entries: &[Entry], key: &str) -> Result<Option<u64>> {
    let Some(e) = get(entries, key) else {
        return Ok(None);
    };
    if e.kind != "integer" {
        return Err(bad(&alloc::format!("{key} is not an <integer>")));
    }
    let t = e.text.trim();
    let t = t.strip_prefix('+').unwrap_or(t);
    if t.is_empty() || t.len() > 20 || !t.bytes().all(|c| c.is_ascii_digit()) {
        return Err(bad(&alloc::format!("{key} is not a non-negative integer")));
    }
    t.parse::<u64>()
        .map(Some)
        .map_err(|_| bad(&alloc::format!("{key} overflows u64")))
}

/// `key` as a `<string>`.
pub fn get_str<'a>(entries: &'a [Entry], key: &str) -> Result<Option<&'a str>> {
    let Some(e) = get(entries, key) else {
        return Ok(None);
    };
    if e.kind != "string" {
        return Err(bad(&alloc::format!("{key} is not a <string>")));
    }
    Ok(Some(e.text.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>band-size</key>
	<integer>8388608</integer>
	<key>bundle-backingstore-version</key>
	<integer>1</integer>
	<key>diskimage-bundle-type</key>
	<string>com.apple.diskimage.sparsebundle</string>
	<key>size</key>
	<integer>67108864</integer>
</dict>
</plist>
"#;

    #[test]
    fn parses_hdiutil_info_plist() {
        let e = parse_dict(APPLE.as_bytes()).unwrap();
        assert_eq!(get_u64(&e, "band-size").unwrap(), Some(8_388_608));
        assert_eq!(get_u64(&e, "size").unwrap(), Some(67_108_864));
        assert_eq!(
            get_str(&e, "diskimage-bundle-type").unwrap(),
            Some("com.apple.diskimage.sparsebundle")
        );
        let span = get(&e, "size").unwrap().text_span.clone();
        assert_eq!(&APPLE[span], "67108864");
    }

    #[test]
    fn skips_nested_and_empty_values() {
        let p = "<plist><dict><key>a</key><dict><key>x</key><array><true/></array></dict>\
                 <key>b</key><false/><key>size</key><integer>5</integer></dict></plist>";
        let e = parse_dict(p.as_bytes()).unwrap();
        assert_eq!(e.len(), 3);
        assert_eq!(get_u64(&e, "size").unwrap(), Some(5));
    }

    #[test]
    fn rejects_malformed() {
        for p in [
            "",
            "<plist><dict><key>size</key><integer>1</integer></plist>",
            "<plist><dict><key>size</key><integer>1</integer><key>size</key><integer>2</integer></dict></plist>",
            "<plist><array></array></plist>",
            "<plist><dict><key>size<b/></key><integer>1</integer></dict></plist>",
            "<plist><dict><key>size</key></dict></plist>",
            "<plist><dict><key>a</key><dict><dict></dict></plist>",
        ] {
            assert!(parse_dict(p.as_bytes()).is_err(), "{p:?}");
        }
        let neg = "<plist><dict><key>size</key><integer>-1</integer></dict></plist>";
        assert!(get_u64(&parse_dict(neg.as_bytes()).unwrap(), "size").is_err());
        let huge =
            "<plist><dict><key>size</key><integer>99999999999999999999999</integer></dict></plist>";
        assert!(get_u64(&parse_dict(huge.as_bytes()).unwrap(), "size").is_err());
        let deep = alloc::format!(
            "<plist><dict><key>a</key>{}{}</dict></plist>",
            "<array>".repeat(100),
            "</array>".repeat(100)
        );
        assert!(parse_dict(deep.as_bytes()).is_err());
        assert!(parse_dict(&alloc::vec![b' '; 70_000]).is_err());
        assert!(parse_dict(b"bplist00....").is_err());
    }
}
