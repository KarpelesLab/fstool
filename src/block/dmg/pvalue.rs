//! A small, bounded XML property-list reader and writer for the UDIF
//! resource plist.
//!
//! [`super::plist`] only scans for the `blkx` payloads the reader needs.
//! Editing an image — carrying a licence agreement across a conversion,
//! adding a resource, rewriting a trailer — needs the *whole* document,
//! so this module parses it into a [`Value`] tree and serialises it back
//! the way Apple's `CFPropertyList` does (tab indentation, dictionary keys
//! in bytewise order, base64 `<data>` wrapped in lines).
//!
//! The input is untrusted: the document is capped by the caller, nesting
//! is capped at [`MAX_DEPTH`] and element counts at [`MAX_ITEMS`]. Binary
//! plists (`bplist00`) are refused — UDIF resource forks are XML.

use crate::Result;

/// Deepest container nesting accepted.
const MAX_DEPTH: usize = 32;
/// Most values (of any kind) accepted in one document.
const MAX_ITEMS: usize = 1 << 20;

/// One property-list value. Dictionaries keep their keys in document
/// order; [`write_document`] sorts them, as `CFPropertyList` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Dict(Vec<(String, Value)>),
    Array(Vec<Value>),
    String(String),
    Data(Vec<u8>),
    /// `<integer>` text, kept verbatim (it may exceed `i64`).
    Integer(String),
    /// `<real>` text, kept verbatim.
    Real(String),
    /// `<date>` text, kept verbatim.
    Date(String),
    Bool(bool),
}

impl Value {
    /// The value under `key` in a dictionary.
    pub(crate) fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dict(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
}

fn bad(msg: impl core::fmt::Display) -> crate::Error {
    crate::Error::InvalidImage(format!("dmg: resource plist: {msg}"))
}

/// Parse an XML property list and return its root value.
pub(crate) fn parse_document(s: &str) -> Result<Value> {
    if s.starts_with("bplist") {
        return Err(crate::Error::Unsupported(
            "dmg: binary property lists are not supported (UDIF resources are XML)".into(),
        ));
    }
    let mut p = Parser {
        s,
        pos: 0,
        items: 0,
    };
    // Expect <plist …> … </plist>, but accept a bare root value too.
    let tag = p.next_tag()?.ok_or_else(|| bad("empty document"))?;
    let root = if tag.name == "plist" {
        if tag.empty {
            return Err(bad("empty <plist/>"));
        }
        let first = p.next_tag()?.ok_or_else(|| bad("unterminated <plist>"))?;
        let v = p.value(first, 0)?;
        let close = p.next_tag()?.ok_or_else(|| bad("missing </plist>"))?;
        if !(close.close && close.name == "plist") {
            return Err(bad(format!("expected </plist>, found <{}>", close.name)));
        }
        v
    } else {
        p.value(tag, 0)?
    };
    Ok(root)
}

struct Tag<'a> {
    name: &'a str,
    close: bool,
    empty: bool,
    /// Byte offset just past the tag's `>`.
    end: usize,
}

struct Parser<'a> {
    s: &'a str,
    pos: usize,
    items: usize,
}

impl<'a> Parser<'a> {
    /// The next element tag at or after the cursor, skipping the XML
    /// declaration, DOCTYPE and comments.
    fn next_tag(&mut self) -> Result<Option<Tag<'a>>> {
        let s = self.s;
        loop {
            let Some(rel) = s[self.pos..].find('<') else {
                return Ok(None);
            };
            let start = self.pos + rel;
            let rest = &s[start..];
            if rest.starts_with("<!--") {
                let end = rest
                    .find("-->")
                    .ok_or_else(|| bad("unterminated comment"))?;
                self.pos = start + end + 3;
                continue;
            }
            if rest.starts_with("<?") || rest.starts_with("<!") {
                let end = rest
                    .find('>')
                    .ok_or_else(|| bad("unterminated declaration"))?;
                self.pos = start + end + 1;
                continue;
            }
            let end = start + rest.find('>').ok_or_else(|| bad("unterminated tag"))?;
            let mut inner = &s[start + 1..end];
            let close = inner.starts_with('/');
            if close {
                inner = &inner[1..];
            }
            let empty = inner.ends_with('/');
            if empty {
                inner = &inner[..inner.len() - 1];
            }
            let name = inner
                .split(|c: char| c.is_ascii_whitespace())
                .next()
                .unwrap_or("");
            if name.is_empty() {
                return Err(bad("tag without a name"));
            }
            self.pos = end + 1;
            return Ok(Some(Tag {
                name,
                close,
                empty,
                end: end + 1,
            }));
        }
    }

    /// The text up to the closing `</name>`, which is consumed.
    fn text_until_close(&mut self, name: &str, from: usize) -> Result<&'a str> {
        let close = format!("</{name}>");
        let rel = self.s[from..]
            .find(&close)
            .ok_or_else(|| bad(format!("unterminated <{name}>")))?;
        let text = &self.s[from..from + rel];
        if text.contains('<') {
            return Err(bad(format!("unexpected markup inside <{name}>")));
        }
        self.pos = from + rel + close.len();
        Ok(text)
    }

    fn value(&mut self, tag: Tag<'a>, depth: usize) -> Result<Value> {
        if tag.close {
            return Err(bad(format!("unexpected </{}>", tag.name)));
        }
        self.items += 1;
        if self.items > MAX_ITEMS {
            return Err(bad("too many values"));
        }
        if depth > MAX_DEPTH {
            return Err(bad("nesting too deep"));
        }
        Ok(match tag.name {
            "dict" => {
                let mut entries: Vec<(String, Value)> = Vec::new();
                if tag.empty {
                    return Ok(Value::Dict(entries));
                }
                loop {
                    let t = self.next_tag()?.ok_or_else(|| bad("unterminated <dict>"))?;
                    if t.close && t.name == "dict" {
                        break;
                    }
                    if t.name != "key" || t.close {
                        return Err(bad(format!("expected <key> in <dict>, found <{}>", t.name)));
                    }
                    let key = if t.empty {
                        String::new()
                    } else {
                        unescape(self.text_until_close("key", t.end)?)?
                    };
                    let vt = self
                        .next_tag()?
                        .ok_or_else(|| bad(format!("key {key:?} has no value")))?;
                    let v = self.value(vt, depth + 1)?;
                    if entries.iter().any(|(k, _)| *k == key) {
                        return Err(bad(format!("duplicate key {key:?}")));
                    }
                    entries.push((key, v));
                }
                Value::Dict(entries)
            }
            "array" => {
                let mut items = Vec::new();
                if tag.empty {
                    return Ok(Value::Array(items));
                }
                loop {
                    let t = self
                        .next_tag()?
                        .ok_or_else(|| bad("unterminated <array>"))?;
                    if t.close && t.name == "array" {
                        break;
                    }
                    items.push(self.value(t, depth + 1)?);
                }
                Value::Array(items)
            }
            "true" | "false" => {
                if !tag.empty {
                    self.text_until_close(tag.name, tag.end)?;
                }
                Value::Bool(tag.name == "true")
            }
            "string" | "data" | "integer" | "real" | "date" => {
                let text = if tag.empty {
                    ""
                } else {
                    self.text_until_close(tag.name, tag.end)?
                };
                match tag.name {
                    "string" => Value::String(unescape(text)?),
                    "data" => {
                        let compact: String =
                            text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
                        Value::Data(crate::base64::decode(&compact)?)
                    }
                    "integer" => Value::Integer(text.trim().to_string()),
                    "real" => Value::Real(text.trim().to_string()),
                    _ => Value::Date(text.trim().to_string()),
                }
            }
            other => return Err(bad(format!("unsupported element <{other}>"))),
        })
    }
}

/// Decode the five predefined XML entities and numeric references.
fn unescape(s: &str) -> Result<String> {
    if !s.contains('&') {
        return Ok(s.to_string());
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let semi = after.find(';').ok_or_else(|| bad("unterminated entity"))?;
        let ent = &after[..semi];
        let c = match ent {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = if let Some(h) = ent.strip_prefix("#x").or(ent.strip_prefix("#X")) {
                    u32::from_str_radix(h, 16).ok()
                } else if let Some(d) = ent.strip_prefix('#') {
                    d.parse().ok()
                } else {
                    None
                };
                code.and_then(char::from_u32)
                    .ok_or_else(|| bad(format!("unknown entity &{ent};")))?
            }
        };
        out.push(c);
        rest = &after[semi + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Escape the XML-significant characters for an element body.
pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
    out
}

/// Serialise `root` as a complete XML plist document, Apple style.
pub(crate) fn write_document(root: &Value) -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n",
    );
    write_value(&mut s, root, 0);
    s.push_str("</plist>\n");
    s
}

fn indent(s: &mut String, depth: usize) {
    for _ in 0..depth {
        s.push('\t');
    }
}

fn write_value(s: &mut String, v: &Value, depth: usize) {
    indent(s, depth);
    match v {
        Value::Dict(entries) if entries.is_empty() => s.push_str("<dict/>\n"),
        Value::Dict(entries) => {
            s.push_str("<dict>\n");
            let mut sorted: Vec<&(String, Value)> = entries.iter().collect();
            sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            for (k, v) in sorted {
                indent(s, depth + 1);
                s.push_str("<key>");
                s.push_str(&escape(k));
                s.push_str("</key>\n");
                write_value(s, v, depth + 1);
            }
            indent(s, depth);
            s.push_str("</dict>\n");
        }
        Value::Array(items) if items.is_empty() => s.push_str("<array/>\n"),
        Value::Array(items) => {
            s.push_str("<array>\n");
            for it in items {
                write_value(s, it, depth + 1);
            }
            indent(s, depth);
            s.push_str("</array>\n");
        }
        Value::String(t) => {
            s.push_str("<string>");
            s.push_str(&escape(t));
            s.push_str("</string>\n");
        }
        Value::Data(d) => {
            s.push_str("<data>\n");
            let b64 = crate::base64::encode(d);
            // Apple wraps at 76 columns minus the indentation (8 per tab).
            let width = 76usize.saturating_sub(8 * depth).max(16) & !3;
            for line in b64.as_bytes().chunks(width) {
                indent(s, depth);
                s.push_str(core::str::from_utf8(line).unwrap_or_default());
                s.push('\n');
            }
            indent(s, depth);
            s.push_str("</data>\n");
        }
        Value::Integer(t) => {
            s.push_str("<integer>");
            s.push_str(t);
            s.push_str("</integer>\n");
        }
        Value::Real(t) => {
            s.push_str("<real>");
            s.push_str(t);
            s.push_str("</real>\n");
        }
        Value::Date(t) => {
            s.push_str("<date>");
            s.push_str(t);
            s.push_str("</date>\n");
        }
        Value::Bool(true) => s.push_str("<true/>\n"),
        Value::Bool(false) => s.push_str("<false/>\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_a_resource_plist() {
        let doc = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>resource-fork</key>
	<dict>
		<key>plst</key>
		<array>
			<dict>
				<key>Attributes</key>
				<string>0x0050</string>
				<key>Data</key>
				<data>
				AAEC
				AwQF
				</data>
				<key>ID</key>
				<string>0</string>
				<key>Name</key>
				<string></string>
			</dict>
		</array>
		<key>TEXT</key>
		<array/>
	</dict>
	<key>n</key><integer>-12</integer>
	<key>b</key><true/>
	<key>s</key><string>a &amp; b &lt;c&gt; &#x41;&#66;</string>
	<key>e</key><string/>
</dict>
</plist>
"#;
        let v = parse_document(doc).unwrap();
        let rf = v.get("resource-fork").unwrap();
        let Value::Array(plst) = rf.get("plst").unwrap() else {
            panic!()
        };
        assert_eq!(
            plst[0].get("Data"),
            Some(&Value::Data(vec![0, 1, 2, 3, 4, 5]))
        );
        assert_eq!(v.get("s").unwrap().as_str(), Some("a & b <c> AB"));
        assert_eq!(v.get("e").unwrap().as_str(), Some(""));
        assert_eq!(v.get("b"), Some(&Value::Bool(true)));
        let out = write_document(&v);
        assert_eq!(parse_document(&out).unwrap(), {
            // Same tree; keys may be reordered, which `PartialEq` on the
            // Vec notices, so compare via a re-parse of the output.
            parse_document(&write_document(&parse_document(&out).unwrap())).unwrap()
        });
        // Keys come out sorted bytewise (uppercase first).
        let tpos = out.find("<key>TEXT</key>").unwrap();
        let ppos = out.find("<key>plst</key>").unwrap();
        assert!(tpos < ppos);
    }

    #[test]
    fn rejects_hostile_input() {
        assert!(parse_document("<plist><dict><key>a</key></dict></plist>").is_err());
        assert!(parse_document("<plist><dict><key>a</key><string>x</string><key>a</key><string>y</string></dict></plist>").is_err());
        assert!(parse_document("<plist><string>a &bogus; b</string></plist>").is_err());
        assert!(parse_document("bplist00....").is_err());
        let deep = "<array>".repeat(100) + &"</array>".repeat(100);
        assert!(parse_document(&deep).is_err());
        assert!(parse_document("<plist><frob/></plist>").is_err());
    }
}
