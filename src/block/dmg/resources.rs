//! The UDIF resource map — the `resource-fork` dictionary of the image's
//! XML plist — as an editable value.
//!
//! A UDIF image keeps what classic Mac OS kept in a file's resource fork
//! in an XML property list instead: a dictionary from four-character
//! resource *type* to an array of resources, each with an `ID`, a `Name`,
//! `Attributes` and its `Data`. `blkx` (the chunk tables) is one of them;
//! `hdiutil` adds a constant `plst`, and images can carry others — the
//! software licence agreement (`LPic`, `STR#`, `TEXT`, `RTF `, `styl`),
//! legacy checksums (`cSum`), NDIF size records (`nsiz`, `size`), …
//!
//! [`UdifResources`] holds the map. [`UdifResources::to_xml`] writes it in
//! the format `hdiutil udifderez -xml` prints, and
//! [`UdifResources::from_xml`] reads that format (the input of
//! `hdiutil udifrez -xml`), or a whole image plist. Changing an image's
//! resources is [`crate::block::dmg::edit_udif_resources`]; it refuses to
//! touch `blkx`, which describes the image's data.
//!
//! ### Separate resource forks
//!
//! Very old UDIF images can also carry a *binary* resource fork inside the
//! file, pointed to by the trailer's `rsrc_fork_offset` / `_length`. It is
//! not part of this map: [`crate::block::dmg::UdifInfo::legacy_resource_fork`]
//! reports it and [`crate::block::dmg::read_legacy_resource_fork`] returns
//! its bytes, and every rewriting operation refuses such an image unless
//! told, through [`crate::block::dmg::LegacyForkPolicy`], to drop it. A
//! resource fork kept by the *host* filesystem (`file/..namedfork/rsrc`)
//! is never read or written.

use super::pvalue::{self, Value};
use crate::Result;

/// The resource type holding the chunk tables. Resource editing never
/// adds, replaces or removes it.
pub const BLKX_RESOURCE: &str = "blkx";

/// One resource.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct UdifResource {
    /// The four-character resource type, e.g. `"TEXT"` or `"RTF "`.
    pub kind: String,
    /// The resource `ID` (stored as a decimal string).
    pub id: i32,
    /// The resource `Name` (may be empty).
    pub name: String,
    /// `CFName`, which `hdiutil` writes for `blkx` entries; `None` omits
    /// it.
    pub cf_name: Option<String>,
    /// The `Attributes` word (stored as `0x%04X`). `hdiutil` writes
    /// `0x0050` for the resources it makes; `udifrez` copies the input's.
    pub attributes: u16,
    /// The resource's bytes.
    pub data: Vec<u8>,
    /// Any other keys of the resource's dictionary, kept verbatim.
    extra: Vec<(String, Value)>,
}

impl UdifResource {
    /// A resource of type `kind` with `id` and `data`, empty name,
    /// attributes 0.
    pub fn new(kind: impl Into<String>, id: i32, data: Vec<u8>) -> Self {
        Self {
            kind: kind.into(),
            id,
            data,
            ..Self::default()
        }
    }

    fn to_value(&self) -> Value {
        let mut d = vec![
            (
                "Attributes".to_string(),
                Value::String(format!("0x{:04X}", self.attributes)),
            ),
            ("Data".to_string(), Value::Data(self.data.clone())),
            ("ID".to_string(), Value::String(self.id.to_string())),
            ("Name".to_string(), Value::String(self.name.clone())),
        ];
        if let Some(cf) = &self.cf_name {
            d.push(("CFName".to_string(), Value::String(cf.clone())));
        }
        d.extend(self.extra.iter().cloned());
        Value::Dict(d)
    }

    fn from_value(kind: &str, v: &Value) -> Result<Self> {
        let Value::Dict(entries) = v else {
            return Err(bad(format!("a {kind:?} resource is not a dictionary")));
        };
        let mut r = Self {
            kind: kind.to_string(),
            ..Self::default()
        };
        let mut have_id = false;
        for (k, v) in entries {
            match (k.as_str(), v) {
                ("Attributes", Value::String(s)) => r.attributes = parse_attributes(s)?,
                ("Attributes", Value::Integer(s)) => r.attributes = parse_attributes(s)?,
                ("Data", Value::Data(d)) => r.data = d.clone(),
                ("ID", Value::String(s) | Value::Integer(s)) => {
                    r.id = s
                        .trim()
                        .parse()
                        .map_err(|_| bad(format!("{kind:?} resource ID {s:?} is not a number")))?;
                    have_id = true;
                }
                ("Name", Value::String(s)) => r.name = s.clone(),
                ("CFName", Value::String(s)) => r.cf_name = Some(s.clone()),
                ("Attributes" | "Data" | "ID" | "Name" | "CFName", _) => {
                    return Err(bad(format!("{kind:?} resource has a malformed {k:?}")));
                }
                _ => r.extra.push((k.clone(), v.clone())),
            }
        }
        if !have_id {
            return Err(bad(format!("a {kind:?} resource has no ID")));
        }
        Ok(r)
    }
}

fn bad(msg: impl core::fmt::Display) -> crate::Error {
    crate::Error::InvalidImage(format!("dmg: resources: {msg}"))
}

fn parse_attributes(s: &str) -> Result<u16> {
    let t = s.trim();
    let v = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u16::from_str_radix(h, 16).ok()
    } else {
        t.parse().ok()
    };
    v.ok_or_else(|| bad(format!("resource attributes {s:?} are not a 16-bit number")))
}

/// Check a resource type: exactly four characters, none of them control
/// characters.
#[cfg_attr(not(any(test, feature = "dmg-write")), allow(dead_code))]
pub(crate) fn check_kind(kind: &str) -> Result<()> {
    if kind.chars().count() != 4 || kind.chars().any(char::is_control) {
        return Err(crate::Error::InvalidArgument(format!(
            "dmg: resource type {kind:?} must be four printable characters (e.g. \"TEXT\", \"RTF \")"
        )));
    }
    Ok(())
}

/// The resource map of a UDIF image: every resource, grouped by type.
///
/// Types keep the order they were first seen in; resources within a type
/// keep theirs. (The image's plist is written with types in bytewise
/// order, as `hdiutil` does.)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct UdifResources {
    /// The resources.
    pub entries: Vec<UdifResource>,
}

impl UdifResources {
    /// No resources.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse resources from XML: either the `udifderez -xml` /
    /// `udifrez -xml` form (a dictionary from type to array of resources)
    /// or a whole UDIF plist (whose `resource-fork` dictionary is used).
    pub fn from_xml(xml: &str) -> Result<Self> {
        let root = pvalue::parse_document(xml)?;
        let map = root.get("resource-fork").unwrap_or(&root);
        Self::from_value(map)
    }

    /// The resources in the form `hdiutil udifderez -xml` prints — which
    /// is also what `hdiutil udifrez -xml` (and [`Self::from_xml`]) reads.
    pub fn to_xml(&self) -> String {
        pvalue::write_document(&self.to_value())
    }

    /// The distinct resource types, in order.
    pub fn kinds(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for r in &self.entries {
            if !out.contains(&r.kind.as_str()) {
                out.push(&r.kind);
            }
        }
        out
    }

    /// The resource of type `kind` with `id`, if any.
    pub fn get(&self, kind: &str, id: i32) -> Option<&UdifResource> {
        self.entries.iter().find(|r| r.kind == kind && r.id == id)
    }

    /// Every resource of type `kind`.
    pub fn of_kind<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a UdifResource> + 'a {
        self.entries.iter().filter(move |r| r.kind == kind)
    }

    /// Add `r`, replacing a resource with the same type and ID.
    pub fn insert(&mut self, r: UdifResource) {
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|e| e.kind == r.kind && e.id == r.id)
        {
            *slot = r;
        } else {
            self.entries.push(r);
        }
    }

    /// Remove the resources of type `kind` (only `id`, when given);
    /// returns how many were removed.
    pub fn remove(&mut self, kind: &str, id: Option<i32>) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|r| !(r.kind == kind && id.is_none_or(|i| r.id == i)));
        before - self.entries.len()
    }

    /// The map as a plist dictionary.
    pub(crate) fn to_value(&self) -> Value {
        let mut map: Vec<(String, Value)> = Vec::new();
        for r in &self.entries {
            let v = r.to_value();
            match map.iter_mut().find(|(k, _)| *k == r.kind) {
                Some((_, Value::Array(a))) => a.push(v),
                _ => map.push((r.kind.clone(), Value::Array(vec![v]))),
            }
        }
        Value::Dict(map)
    }

    /// Read a `resource-fork`-shaped dictionary.
    pub(crate) fn from_value(map: &Value) -> Result<Self> {
        let Value::Dict(kinds) = map else {
            return Err(bad("the resource map is not a dictionary"));
        };
        let mut out = Self::default();
        for (kind, list) in kinds {
            let Value::Array(items) = list else {
                return Err(bad(format!("resource type {kind:?} is not an array")));
            };
            for it in items {
                out.entries.push(UdifResource::from_value(kind, it)?);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_roundtrip_matches_udifderez_shape() {
        let mut rs = UdifResources::new();
        let mut t = UdifResource::new("TEXT", 5000, b"Licence & terms".to_vec());
        t.name = "English SLA".into();
        rs.insert(t);
        rs.insert(UdifResource::new(
            "LPic",
            5000,
            vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        ));
        rs.insert(UdifResource::new("RTF ", 5000, b"{\\rtf1}".to_vec()));
        let xml = rs.to_xml();
        assert!(xml.contains("<key>RTF </key>"));
        assert!(xml.contains("<string>0x0000</string>"));
        let back = UdifResources::from_xml(&xml).unwrap();
        for r in &rs.entries {
            assert_eq!(back.get(&r.kind, r.id), Some(r));
        }
        // Replacing by (type, ID).
        rs.insert(UdifResource::new("TEXT", 5000, b"new".to_vec()));
        assert_eq!(rs.of_kind("TEXT").count(), 1);
        assert_eq!(rs.get("TEXT", 5000).unwrap().data, b"new");
        assert_eq!(rs.remove("LPic", None), 1);
        assert_eq!(rs.kinds(), ["TEXT", "RTF "]);
    }

    #[test]
    fn whole_image_plists_and_extra_keys() {
        let xml = r#"<plist version="1.0"><dict><key>resource-fork</key><dict>
            <key>plst</key><array><dict><key>Attributes</key><string>0x0050</string>
            <key>Data</key><data>AAE=</data><key>ID</key><string>0</string>
            <key>Name</key><string></string><key>Weird</key><integer>7</integer></dict></array>
            </dict></dict></plist>"#;
        let rs = UdifResources::from_xml(xml).unwrap();
        let p = rs.get("plst", 0).unwrap();
        assert_eq!((p.attributes, p.data.as_slice()), (0x50, &[0u8, 1][..]));
        // Unknown keys survive a round trip.
        assert!(rs.to_xml().contains("<key>Weird</key>"));
        assert!(
            UdifResources::from_xml("<plist><dict><key>x</key><string/></dict></plist>").is_err()
        );
        assert!(
            UdifResources::from_xml(
                "<plist><dict><key>TEXT</key><array><dict><key>Data</key><data/></dict></array></dict></plist>"
            )
            .is_err(),
            "a resource without an ID is malformed"
        );
        assert!(check_kind("TEXT").is_ok());
        assert!(check_kind("TXT").is_err());
        assert!(check_kind("TE\nT").is_err());
    }
}
