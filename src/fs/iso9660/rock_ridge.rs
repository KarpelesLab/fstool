//! Rock Ridge (IEEE P1282) System Use Sharing Protocol entries.
//!
//! We parse the entries we surface through the read API:
//!
//! - `SP` (System Use Protocol indicator) — must appear on the "." entry
//!   of the root directory for RR to be active.
//! - `RR` — bit-flags advertising which other entries to expect (older
//!   convention; newer media drops it).
//! - `NM` — alternate (long) name. Concatenates across `CONTINUE` flag.
//! - `PX` — POSIX file mode + nlink + uid + gid. Bytes 4..36, both-endian.
//! - `SL` — symlink target. Composed of `Component Records`.
//! - `CE` — continuation area pointer (LBA + offset + length). When set,
//!   the remaining SUA bytes live at that location.
//! - `TF` — timestamps. We pick mtime out of it for the user-facing API.
//!
//! Everything else (`PN`, `CL`, `PL`, `SF`, vendor-specific) is parsed far
//! enough to be skipped over.

use crate::Result;
use crate::block::BlockDevice;

use super::SECTOR_SIZE;
use super::directory::DirRecord;
use super::vd::PrimaryVolumeDescriptor;

/// Cooked Rock Ridge attributes for one directory entry. Only the
/// fields the read path needs are kept; the writer constructs SUA bytes
/// directly without going through this struct.
#[derive(Debug, Default, Clone)]
pub struct RockRidgeAttrs {
    pub alternate_name: Option<String>,
    pub symlink_target: Option<String>,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mtime: Option<i64>,
}

/// Walk the System Use Area of a directory record and produce the
/// cooked attributes. Returns `None` if the SUA contained nothing of
/// interest (the caller can then fall back to defaults).
pub fn parse_system_use(dev: &mut dyn BlockDevice, sua: &[u8]) -> Option<RockRidgeAttrs> {
    let mut acc = Acc {
        attrs: RockRidgeAttrs::default(),
        name: String::new(),
        symlink: String::new(),
        sl_need_sep: false,
        any: false,
        ce_budget: MAX_CE_FOLLOWS,
    };

    parse_block(sua, dev, &mut acc);

    if !acc.any {
        return None;
    }
    let mut attrs = acc.attrs;
    if !acc.name.is_empty() {
        attrs.alternate_name = Some(acc.name);
    }
    if !acc.symlink.is_empty() {
        attrs.symlink_target = Some(acc.symlink);
    }
    Some(attrs)
}

/// Accumulator threaded through one record's SUA and every continuation
/// area it points at, so multi-entry `NM` / `SL` state and the `CE`
/// budget are shared across all of them.
struct Acc {
    attrs: RockRidgeAttrs,
    name: String,
    symlink: String,
    /// Whether the next `SL` component must be preceded by a `/`. False
    /// at the start, after a ROOT component, and after a component whose
    /// CONTINUE flag says the next record continues the same name.
    sl_need_sep: bool,
    any: bool,
    /// Continuation areas we may still follow for this record.
    ce_budget: usize,
}

/// Detect SP / ER on the root's "." entry. If present, Rock Ridge is
/// active for the whole volume.
pub fn root_has_rr(dev: &mut dyn BlockDevice, pvd: &PrimaryVolumeDescriptor) -> Result<bool> {
    // The root directory's first record (".") sits at the very start
    // of the root extent. Read one sector and decode.
    let mut buf = vec![0u8; SECTOR_SIZE as usize];
    dev.read_at(
        u64::from(pvd.root.extent_lba) * u64::from(SECTOR_SIZE),
        &mut buf,
    )?;
    if buf.is_empty() || buf[0] == 0 {
        return Ok(false);
    }
    let len_dr = buf[0] as usize;
    if len_dr < 33 || len_dr > buf.len() {
        return Ok(false);
    }
    let dot = DirRecord::decode(&buf[..len_dr])?;
    // SP entry (SUSP §5.3): "SP" + len (>= 7) + version + 0xBE 0xEF +
    // bytes-skipped. The SUA may hold nothing but this 7-byte entry, so
    // the scan must consider a candidate that ends exactly at the end.
    let sua = &dot.system_use;
    Ok(sua
        .windows(7)
        .any(|w| &w[..2] == b"SP" && w[2] >= 7 && w[4] == 0xBE && w[5] == 0xEF))
}

/// Maximum number of `CE` continuation areas we will follow for a single
/// directory record, counted across the whole record (not per nesting
/// level). A malicious image can otherwise chain, fan out or cycle `CE`
/// entries to drive unbounded disk reads.
const MAX_CE_FOLLOWS: usize = 8;

/// Walk a contiguous SUA block, mutating the accumulator in place.
/// A `CE` entry continues into its continuation area on disk; per IEEE
/// P1282 §4.1.5 it is the last entry of the area it sits in, so nothing
/// after it is looked at.
fn parse_block(sua: &[u8], dev: &mut dyn BlockDevice, acc: &mut Acc) {
    let mut i = 0;
    while i + 4 <= sua.len() {
        let sig = &sua[i..i + 2];
        let len = sua[i + 2] as usize;
        if len < 4 || i + len > sua.len() {
            break;
        }
        let body = &sua[i + 4..i + len];
        match sig {
            b"NM" => {
                if let Some(payload) = body.get(1..) {
                    // body[0] is the flags byte; bit 0 (CONTINUE) just
                    // means another NM follows — we concatenate regardless.
                    acc.name.push_str(&String::from_utf8_lossy(payload));
                    acc.any = true;
                }
            }
            b"PX" if body.len() >= 32 => {
                if let Ok(mode) = super::vd::decode_both_endian_u32(&body[0..8], "PX.mode") {
                    acc.attrs.mode = Some(mode);
                }
                // nlink (body[8..16]) is parsed by the spec but not surfaced today.
                if let Ok(uid) = super::vd::decode_both_endian_u32(&body[16..24], "PX.uid") {
                    acc.attrs.uid = Some(uid);
                }
                if let Ok(gid) = super::vd::decode_both_endian_u32(&body[24..32], "PX.gid") {
                    acc.attrs.gid = Some(gid);
                }
                acc.any = true;
            }
            b"SL" => {
                // body[0] = flags (bit 0: another SL entry continues this
                // same target), body[1..] = component records. Separator
                // state lives in `acc` so it carries across SL entries.
                let mut j = 1;
                while j + 2 <= body.len() {
                    let comp_flags = body[j];
                    let comp_len = body[j + 1] as usize;
                    if j + 2 + comp_len > body.len() {
                        break;
                    }
                    let comp_bytes = &body[j + 2..j + 2 + comp_len];
                    // Bit flags per IEEE P1282 §4.1.3.1:
                    //   0x01: CONTINUE — this component's text continues
                    //         in the next component record (no slash)
                    //   0x02: CURRENT  ("." )
                    //   0x04: PARENT   ("..")
                    //   0x08: ROOT     ("/")
                    if comp_flags & 0x08 != 0 {
                        // ROOT is the leading `/` itself; the next
                        // component follows it directly.
                        acc.symlink.push('/');
                        acc.sl_need_sep = false;
                    } else {
                        if acc.sl_need_sep {
                            acc.symlink.push('/');
                        }
                        if comp_flags & 0x02 != 0 {
                            acc.symlink.push('.');
                        } else if comp_flags & 0x04 != 0 {
                            acc.symlink.push_str("..");
                        } else {
                            acc.symlink.push_str(&String::from_utf8_lossy(comp_bytes));
                        }
                        acc.sl_need_sep = comp_flags & 0x01 == 0;
                    }
                    j += 2 + comp_len;
                }
                acc.any = true;
            }
            b"CE" if body.len() >= 24 => {
                // Bound disk reads: stop following continuation areas once
                // the record's budget is spent. This also breaks any CE
                // cycle a malicious image builds.
                if acc.ce_budget == 0 {
                    break;
                }
                acc.ce_budget -= 1;
                let ce_lba = super::vd::decode_both_endian_u32(&body[0..8], "CE.lba").ok();
                let ce_off = super::vd::decode_both_endian_u32(&body[8..16], "CE.offset").ok();
                let ce_len = super::vd::decode_both_endian_u32(&body[16..24], "CE.len").ok();
                if let (Some(lba), Some(off), Some(clen)) = (ce_lba, ce_off, ce_len) {
                    // The continuation area lives within one logical sector;
                    // a SUA cannot span sectors. Reject any (offset, length)
                    // that would read past a single sector — this caps the
                    // attacker-controlled allocation to SECTOR_SIZE.
                    let off = off as u64;
                    let clen = clen as u64;
                    let sector = u64::from(SECTOR_SIZE);
                    if clen == 0 || off >= sector || off + clen > sector {
                        // Out-of-range continuation pointer — ignore it.
                    } else {
                        let mut buf = vec![0u8; clen as usize];
                        let abs = u64::from(lba) * sector + off;
                        if dev.read_at(abs, &mut buf).is_ok() {
                            parse_block(&buf, dev, acc);
                        }
                    }
                }
                // CE is by spec the last entry of its area.
                break;
            }
            b"TF" => {
                // Timestamps. body[0] = flags bitmap (0x01 creation,
                // 0x02 modify, 0x04 access, ...). Each timestamp is 7
                // bytes (or 17 if flag bit 0x80 is set for long form).
                let flags = body.first().copied().unwrap_or(0);
                let long = flags & 0x80 != 0;
                let entry_size = if long { 17 } else { 7 };
                let bits = flags & 0x7F;
                let mut k = 1;
                // We want bit 0x02 (modify time).
                let mut bit = 0u8;
                while bit < 7 {
                    if bits & (1 << bit) != 0 && k + entry_size <= body.len() {
                        if bit == 1 {
                            let ts = &body[k..k + entry_size];
                            acc.attrs.mtime = Some(if long {
                                decode_iso_long_time(ts)
                            } else {
                                decode_iso_short_time(ts)
                            });
                        }
                        k += entry_size;
                    }
                    bit += 1;
                }
                acc.any = true;
            }
            b"SP" | b"RR" | b"ER" | b"ES" | b"PD" | b"ST" | b"PN" | b"CL" | b"PL" | b"SF" => {
                acc.any = true;
            }
            _ => { /* unknown / vendor entry — skip */ }
        }
        i += len;
    }
}

/// ECMA-119 §9.1.5 short-form time: 7 bytes — years since 1900, month,
/// day, hour, minute, second, GMT offset (15-minute units).
fn decode_iso_short_time(buf: &[u8]) -> i64 {
    if buf.len() < 7 {
        return 0;
    }
    let years = i64::from(buf[0]);
    let month = i64::from(buf[1]);
    let day = i64::from(buf[2]);
    let hour = i64::from(buf[3]);
    let minute = i64::from(buf[4]);
    let second = i64::from(buf[5]);
    let gmt_off_qh = i8::from_le_bytes([buf[6]]) as i64;
    // Days-from-civil — Howard Hinnant.
    let y = 1900 + years - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m_shift = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * m_shift + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + hour * 3600 + minute * 60 + second - gmt_off_qh * 15 * 60
}

/// ECMA-119 §8.4.26.1 long-form time: 16 ASCII digits
/// `YYYYMMDDHHMMSScc` (the trailing `cc` is hundredths of a second)
/// followed by one GMT-offset byte in 15-minute units. Converted through
/// the short-form path so both forms share one calendar computation.
fn decode_iso_long_time(buf: &[u8]) -> i64 {
    if buf.len() < 17 {
        return 0;
    }
    let digits = |r: std::ops::Range<usize>| -> Option<i64> {
        buf[r].iter().try_fold(0i64, |acc, &b| {
            if b.is_ascii_digit() {
                Some(acc * 10 + i64::from(b - b'0'))
            } else {
                None
            }
        })
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        digits(0..4),
        digits(4..6),
        digits(6..8),
        digits(8..10),
        digits(10..12),
        digits(12..14),
    ) else {
        return 0;
    };
    // An all-zero field set means "not specified".
    if year == 0 {
        return 0;
    }
    let years = year - 1900;
    if !(0..=255).contains(&years) {
        return 0;
    }
    let short = [
        years as u8,
        month as u8,
        day as u8,
        hour as u8,
        minute as u8,
        second as u8,
        buf[16],
    ];
    decode_iso_short_time(&short)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;

    /// Build one SUSP entry: signature, length, version 1, body.
    fn entry(sig: &[u8; 2], body: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + body.len());
        v.extend_from_slice(sig);
        v.push((4 + body.len()) as u8);
        v.push(1);
        v.extend_from_slice(body);
        v
    }

    /// One SL component record.
    fn comp(flags: u8, text: &[u8]) -> Vec<u8> {
        let mut v = vec![flags, text.len() as u8];
        v.extend_from_slice(text);
        v
    }

    fn parse(sua: &[u8]) -> RockRidgeAttrs {
        let mut dev = MemoryBackend::new(4 * SECTOR_SIZE as u64);
        parse_system_use(&mut dev, sua).expect("attrs")
    }

    /// Absolute targets start with a single `/`, and components are
    /// separated by exactly one `/`.
    #[test]
    fn sl_absolute_target_has_single_leading_slash() {
        let mut body = vec![0u8];
        body.extend(comp(0x08, b""));
        body.extend(comp(0, b"usr"));
        body.extend(comp(0, b"lib"));
        let sua = entry(b"SL", &body);
        assert_eq!(parse(&sua).symlink_target.as_deref(), Some("/usr/lib"));

        let mut body = vec![0u8];
        body.extend(comp(0x04, b""));
        body.extend(comp(0x02, b""));
        body.extend(comp(0, b"x"));
        let sua = entry(b"SL", &body);
        assert_eq!(parse(&sua).symlink_target.as_deref(), Some(".././x"));
    }

    /// A component's CONTINUE flag glues the next record to it without a
    /// separator, and the state carries across SL entries.
    #[test]
    fn sl_continue_flag_concatenates_components() {
        let mut body1 = vec![0x01u8]; // SL-level CONTINUE: another SL follows
        body1.extend(comp(0, b"dir"));
        body1.extend(comp(0x01, b"long-na"));
        let mut body2 = vec![0u8];
        body2.extend(comp(0, b"me.txt"));
        let mut sua = entry(b"SL", &body1);
        sua.extend(entry(b"SL", &body2));
        assert_eq!(
            parse(&sua).symlink_target.as_deref(),
            Some("dir/long-name.txt")
        );
    }

    /// TF long form (17-byte ASCII timestamps) decodes to the same instant
    /// as the equivalent short form.
    #[test]
    fn tf_long_form_matches_short_form() {
        // 2024-03-05 06:07:08 UTC.
        let short = [124u8, 3, 5, 6, 7, 8, 0];
        let mut long = b"2024030506070800".to_vec();
        long.push(0);
        let mut b_short = vec![0x02u8];
        b_short.extend_from_slice(&short);
        let mut b_long = vec![0x82u8];
        b_long.extend_from_slice(&long);
        let t_short = parse(&entry(b"TF", &b_short)).mtime.unwrap();
        let t_long = parse(&entry(b"TF", &b_long)).mtime.unwrap();
        assert_eq!(t_short, t_long);
        assert_eq!(t_short, 1_709_618_828);
    }

    /// A CE that points back at itself (or fans out) is followed at most
    /// MAX_CE_FOLLOWS times in total, and nothing after a CE is parsed.
    #[test]
    fn ce_cycle_is_bounded() {
        let sector = SECTOR_SIZE as u64;
        let mut dev = MemoryBackend::new(4 * sector);
        // Continuation area at LBA 1, offset 0: an NM entry, then a CE that
        // points back at itself, then another NM that must never be seen.
        let mut ce_body = Vec::new();
        for v in [1u32, 0, 64] {
            ce_body.extend_from_slice(&v.to_le_bytes());
            ce_body.extend_from_slice(&v.to_be_bytes());
        }
        let mut area = entry(b"NM", &[0, b'a']);
        area.extend(entry(b"CE", &ce_body));
        area.extend(entry(b"NM", &[0, b'Z']));
        assert!(area.len() <= 64);
        area.resize(64, 0);
        dev.write_at(sector, &area).unwrap();
        let sua = entry(b"CE", &ce_body);
        let attrs = parse_system_use(&mut dev, &sua).unwrap();
        let name = attrs.alternate_name.unwrap();
        assert_eq!(name.len(), MAX_CE_FOLLOWS);
        assert!(name.bytes().all(|b| b == b'a'), "{name}");
    }
}
