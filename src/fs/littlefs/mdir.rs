//! Metadata pairs — littlefs's unit of metadata storage.
//!
//! A metadata pair is two blocks. Each block is a 32-bit revision count
//! followed by an append-only log of *commits*; each commit is a run of
//! tag+data entries terminated by a CRC tag. The block of the pair with the
//! newer revision count that still has a valid commit is the live one.
//!
//! [`fetch`] replays a pair's log into the flat [`Mdir`] view the rest of
//! the backend works with: a `Vec<Entry>` indexed by file id, the pair's
//! tail pointer, and any global-state delta. [`Mdir::commit`] goes the other
//! way, writing the whole state back as a single fresh commit (a
//! *compaction*) into the pair's stale block, then swapping the pair so the
//! newly written block is the live one. That is the same operation littlefs
//! performs whenever a metadata block fills up or isn't in a known-erased
//! state; always taking it keeps the writer simple and every image we
//! produce is one a stock littlefs can mount and keep appending to.

use crate::block::BlockDevice;
use crate::{Error, Result};

use super::tag::{self, Tag};

/// Geometry + format flavour of a littlefs volume. Fixed at format time
/// (block size / count are recorded in the superblock) except for
/// `prog_size`, which is a property of the target flash, not the image.
#[derive(Debug, Clone, Copy)]
pub struct Geom {
    /// Logical block (erase unit) size.
    pub block_size: u32,
    /// Number of blocks in the volume.
    pub block_count: u32,
    /// Program alignment commits are padded to. Also the size of the window
    /// an FCRC covers.
    pub prog_size: u32,
    /// Whether to emit lfs2.1 forward-CRC tags. Off for images pinned to
    /// disk version 2.0, whose readers mistake an FCRC for a commit CRC.
    pub fcrc: bool,
}

impl Geom {
    /// Byte offset of `block` on the device.
    pub fn offset(&self, block: u32) -> u64 {
        block as u64 * self.block_size as u64
    }

    /// Largest total size of a pair's *entries* that a metadata block can
    /// still hold once everything a commit appends to them is accounted
    /// for: the tail (4+8), a global-state delta (4+12), the forward-CRC
    /// (4+8) and the commit CRC (4+4). Padding needs no allowance, since
    /// both the block and the program size are powers of two.
    pub fn commit_limit(&self) -> usize {
        self.block_size as usize - 48
    }

    /// Size past which a metadata pair is split in two. littlefs caps a
    /// compaction at half a block so a pair that is repeatedly appended to
    /// doesn't degenerate into one that must compact on every commit.
    pub fn split_limit(&self) -> usize {
        let half = (self.block_size as usize / 2).next_multiple_of(self.prog_size.max(1) as usize);
        half.min(self.commit_limit())
    }
}

/// The on-disk structure attached to a file id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Struct {
    /// Directory: pointer to the first metadata pair of the directory.
    Dir([u32; 2]),
    /// Small file stored directly in the metadata block.
    Inline(Vec<u8>),
    /// File stored as a CTZ skip-list rooted at `head`.
    Ctz { head: u32, size: u32 },
}

/// One file id within a metadata pair.
#[derive(Debug, Clone, Default)]
pub struct Entry {
    /// Chunk field of the name tag: [`tag::TYPE_REG`], [`tag::TYPE_DIR`] or
    /// [`tag::TYPE_SUPERBLOCK`]. Zero for an id created by a splice whose
    /// name tag hasn't been seen (never happens in a compacted block).
    pub kind: u8,
    /// File name, as stored (littlefs names are byte strings).
    pub name: Vec<u8>,
    /// Struct tag contents, if any.
    pub data: Option<Struct>,
    /// User attributes, keyed by the 8-bit attribute type.
    pub attrs: Vec<(u8, Vec<u8>)>,
}

impl Entry {
    /// Whether this id is a real filesystem entry. The superblock shares the
    /// root directory's metadata pair as id 0 but is not a file — littlefs
    /// filters it out of directory listings by masking the name tag's type,
    /// and so do we.
    pub fn is_file(&self) -> bool {
        self.kind == tag::TYPE_REG as u8 || self.kind == tag::TYPE_DIR as u8
    }

    /// Bytes this entry occupies in a commit: its name tag, struct tag and
    /// every user attribute.
    fn commit_size(&self) -> usize {
        let mut n = 4 + self.name.len();
        n += match &self.data {
            Some(Struct::Dir(_)) | Some(Struct::Ctz { .. }) => 4 + 8,
            Some(Struct::Inline(d)) => 4 + d.len(),
            None => 0,
        };
        for (_, v) in &self.attrs {
            n += 4 + v.len();
        }
        n
    }
}

/// A metadata pair, replayed into a flat view.
#[derive(Debug, Clone)]
pub struct Mdir {
    /// The pair's blocks, live one first.
    pub pair: [u32; 2],
    /// Revision count of the live block.
    pub rev: u32,
    /// Files in this block, indexed by id.
    pub entries: Vec<Entry>,
    /// Next metadata pair in the threaded list, if any.
    pub tail: Option<[u32; 2]>,
    /// Whether `tail` is a *hard* tail — the continuation of this same
    /// directory — rather than a soft one that merely threads the list.
    pub hard: bool,
    /// Global-state delta carried by this pair, preserved verbatim. The
    /// filesystem's global state is the XOR of every pair's delta, so a
    /// rewrite that dropped it would corrupt the sum.
    pub gdelta: Option<[u8; 12]>,
    /// Window size of the last forward-CRC seen while replaying the log.
    /// That is the program size the volume's previous writer used, which is
    /// the only place it is recorded — the superblock doesn't carry it.
    pub fcrc_size: Option<u32>,
}

impl Mdir {
    /// An empty pair, not yet written to disk.
    pub fn empty(pair: [u32; 2]) -> Self {
        Self {
            pair,
            rev: 0,
            entries: Vec::new(),
            tail: None,
            hard: false,
            gdelta: None,
            fcrc_size: None,
        }
    }

    /// Find an entry by name, returning its id.
    pub fn find(&self, name: &[u8]) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.is_file() && e.name == name)
    }

    /// Total size of this pair's entries. The tail and global-state
    /// tags a commit appends are *not* counted here: they are what
    /// [`Geom::commit_limit`] holds back room for, and counting them
    /// twice would make a pair look unsplittable when it merely needs
    /// its last entry moved along.
    fn entries_size(&self) -> usize {
        self.entries.iter().map(Entry::commit_size).sum()
    }
}

/// Read a metadata pair and replay its log.
pub fn fetch(dev: &mut dyn BlockDevice, geom: &Geom, pair: [u32; 2]) -> Result<Mdir> {
    for b in pair {
        if b >= geom.block_count {
            return Err(Error::InvalidImage(format!(
                "littlefs: metadata pair block {b} beyond block count {}",
                geom.block_count
            )));
        }
    }

    // Try the block with the newer revision count first; fall back to its
    // partner when it holds no valid commit (a power cut mid-compaction).
    let mut order = pair;
    if let (Some(a), Some(b)) = (read_rev(dev, geom, pair[0]), read_rev(dev, geom, pair[1]))
        && tag::rev_newer(b, a)
    {
        order.swap(0, 1);
    }

    for i in 0..2 {
        let block = order[i];
        if let Some(mut mdir) = parse_block(dev, geom, block)? {
            mdir.pair = [block, order[1 - i]];
            return Ok(mdir);
        }
    }

    Err(Error::InvalidImage(format!(
        "littlefs: corrupted metadata pair {{{}, {}}}",
        pair[0], pair[1]
    )))
}

/// Read just the revision count of a block. `None` when the read fails —
/// treated the same as a corrupt block.
pub fn read_rev(dev: &mut dyn BlockDevice, geom: &Geom, block: u32) -> Option<u32> {
    let mut b = [0u8; 4];
    dev.read_at(geom.offset(block), &mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

/// Replay one block's commits. Returns `None` if the block holds no valid
/// commit at all, otherwise the state as of its last valid commit.
fn parse_block(dev: &mut dyn BlockDevice, geom: &Geom, block: u32) -> Result<Option<Mdir>> {
    let bs = geom.block_size as usize;
    let mut buf = vec![0u8; bs];
    if dev.read_at(geom.offset(block), &mut buf).is_err() {
        return Ok(None);
    }

    let rev = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let mut live: Option<Mdir> = None;
    let mut cur = Mdir::empty([block, block]);
    cur.rev = rev;

    let mut off = 0usize;
    let mut ptag = tag::PTAG_INIT;
    let mut crc = tag::crc(tag::PTAG_INIT, &buf[0..4]);

    loop {
        // Tags are chained: the next one starts right after the previous
        // tag's data. `PTAG_INIT` has an all-ones size field, i.e. "deleted",
        // so the very first step skips exactly the 4-byte revision count.
        off += Tag(ptag).dsize();
        if off + 4 > bs {
            break;
        }
        crc = tag::crc(crc, &buf[off..off + 4]);
        let t = Tag(tag::be32(&buf[off..off + 4]) ^ ptag);
        if !t.is_valid() || off + t.dsize() > bs {
            // Unwritten (or interrupted) storage — end of the log.
            break;
        }
        ptag = t.0;

        if t.type2() == tag::TYPE_CCRC {
            if off + 8 > bs {
                break;
            }
            if crc != tag::le32(&buf[off + 4..off + 8]) {
                break;
            }
            // The CRC tag's low chunk bit flips the valid-bit state the next
            // commit's tags are expected to have.
            ptag ^= ((t.chunk() & 1) as u32) << 31;
            live = Some(cur.clone());
            crc = tag::PTAG_INIT;
            continue;
        }

        let data = &buf[off + 4..off + t.dsize()];
        crc = tag::crc(crc, data);
        apply(&mut cur, t, data);
    }

    Ok(live)
}

/// Fold one tag into the running state. Later tags supersede earlier ones
/// for the same (type, id), which is what makes a metadata block an
/// append-only log of overrides.
fn apply(mdir: &mut Mdir, t: Tag, data: &[u8]) {
    let id = t.id() as usize;
    match t.type1() {
        tag::T1_NAME => {
            grow(mdir, id);
            if let Some(e) = mdir.entries.get_mut(id) {
                e.kind = t.chunk();
                e.name = data.to_vec();
            }
        }
        tag::T1_STRUCT => {
            grow(mdir, id);
            let Some(e) = mdir.entries.get_mut(id) else {
                return;
            };
            // Any struct supersedes any other struct on the same id.
            e.data = match t.type3() {
                tag::TYPE_DIRSTRUCT if data.len() >= 8 => Some(Struct::Dir([
                    tag::le32(&data[0..4]),
                    tag::le32(&data[4..8]),
                ])),
                tag::TYPE_CTZSTRUCT if data.len() >= 8 => Some(Struct::Ctz {
                    head: tag::le32(&data[0..4]),
                    size: tag::le32(&data[4..8]),
                }),
                tag::TYPE_INLINESTRUCT => Some(Struct::Inline(data.to_vec())),
                _ => e.data.take(),
            };
        }
        tag::T1_USERATTR => {
            grow(mdir, id);
            let Some(e) = mdir.entries.get_mut(id) else {
                return;
            };
            let key = t.chunk();
            e.attrs.retain(|(k, _)| *k != key);
            if !t.is_delete() {
                e.attrs.push((key, data.to_vec()));
                e.attrs.sort_by_key(|(k, _)| *k);
            }
        }
        tag::T1_SPLICE => {
            // A create inserts an id (shifting later ids up), a delete
            // removes one (shifting them down) — insertion into and removal
            // from an imaginary array of files.
            match t.type3() {
                tag::TYPE_CREATE => {
                    if id <= mdir.entries.len() {
                        mdir.entries.insert(id, Entry::default());
                    } else {
                        grow(mdir, id);
                    }
                }
                tag::TYPE_DELETE if id < mdir.entries.len() => {
                    mdir.entries.remove(id);
                }
                _ => {}
            }
        }
        tag::T1_TAIL => {
            if data.len() >= 8 {
                mdir.tail = Some([tag::le32(&data[0..4]), tag::le32(&data[4..8])]);
                mdir.hard = t.chunk() & 1 != 0;
            }
        }
        tag::T1_GSTATE => {
            if data.len() >= 12 {
                let mut g = [0u8; 12];
                g.copy_from_slice(&data[..12]);
                mdir.gdelta = Some(g);
            }
        }
        // Commit CRCs are consumed by the parser itself; the only CRC tag
        // that reaches here is the lfs2.1 forward-CRC, whose size field
        // tells us the writer's program alignment.
        tag::T1_CRC if t.type3() == tag::TYPE_FCRC && data.len() >= 8 => {
            mdir.fcrc_size = Some(tag::le32(&data[0..4]));
        }
        _ => {}
    }
}

/// Make room for file id `id`, as a name tag for an id past the current
/// count implicitly does in littlefs.
fn grow(mdir: &mut Mdir, id: usize) {
    // Guard against a corrupt tag claiming a huge id; ids are 10 bits and
    // 0x3ff is reserved for block-level tags, so nothing legitimate is
    // anywhere near this bound.
    if id >= tag::ID_NONE as usize {
        return;
    }
    while mdir.entries.len() <= id {
        mdir.entries.push(Entry::default());
    }
}

/// Builder for a single commit: tags are appended, then [`Self::finish`]
/// closes it out with the CRC tag and returns the block image to write.
struct CommitBuf {
    buf: Vec<u8>,
    ptag: u32,
}

impl CommitBuf {
    fn new(rev: u32) -> Self {
        Self {
            buf: rev.to_le_bytes().to_vec(),
            ptag: tag::PTAG_INIT,
        }
    }

    /// Append one tag and its data.
    fn push(&mut self, t: Tag, data: &[u8]) {
        let stored = (t.0 & 0x7fff_ffff) ^ self.ptag;
        self.buf.extend_from_slice(&stored.to_be_bytes());
        if !t.is_delete() {
            self.buf.extend_from_slice(data);
        }
        self.ptag = t.0 & 0x7fff_ffff;
    }

    /// Close the commit and render the full block image.
    ///
    /// Everything after the commit is left in the erased state (`0xff`), the
    /// convention littlefs's block devices use, so that a real littlefs can
    /// append its next commit here in place. That is also what the optional
    /// forward-CRC records: the checksum of the erased window that follows,
    /// proving to the next mount that nothing was half-programmed into it.
    fn finish(mut self, geom: &Geom) -> Result<Vec<u8>> {
        let bs = geom.block_size as usize;
        let prog = geom.prog_size.max(1) as usize;

        // Room for the FCRC (tag + 8) plus the CRC tag (tag + 4), matching
        // the 5-word window littlefs reserves.
        let reserve = if geom.fcrc { 5 * 4 } else { 2 * 4 };
        let end = (self.buf.len() + reserve).min(bs).next_multiple_of(prog);
        if end > bs {
            return Err(Error::InvalidArgument(
                "littlefs: commit does not fit in a metadata block".into(),
            ));
        }

        // The erased tail: everything from the end of this commit onwards.
        let mut block = vec![0xffu8; bs];

        if geom.fcrc && end <= bs - prog {
            let fcrc_crc = tag::crc(tag::PTAG_INIT, &block[end..end + prog]);
            let mut d = [0u8; 8];
            d[0..4].copy_from_slice(&(prog as u32).to_le_bytes());
            d[4..8].copy_from_slice(&fcrc_crc.to_le_bytes());
            self.push(Tag::new(tag::TYPE_FCRC, tag::ID_NONE, 8), &d);
        }

        // The CRC tag's size field covers the padding up to `end`, so a
        // fetch can skip straight over it. The low chunk bit is chosen so
        // that reading the erased byte at `end` yields an *invalid* tag,
        // which is how the next mount recognises unwritten storage.
        let pad = end - (self.buf.len() + 4);
        if pad > tag::MAX_SIZE {
            return Err(Error::InvalidArgument(
                "littlefs: commit padding exceeds a single CRC tag".into(),
            ));
        }
        let eperturb: u8 = if end < bs { block[end] } else { 0xff };
        let ccrc = Tag::new(
            tag::TYPE_CCRC + ((!eperturb) >> 7) as u16,
            tag::ID_NONE,
            pad as u16,
        );
        let stored = (ccrc.0 & 0x7fff_ffff) ^ self.ptag;
        self.buf.extend_from_slice(&stored.to_be_bytes());

        let crc = tag::crc(tag::PTAG_INIT, &self.buf);
        self.buf.extend_from_slice(&crc.to_le_bytes());

        block[..self.buf.len()].copy_from_slice(&self.buf);
        Ok(block)
    }
}

/// Render `mdir`'s state as a commit body and write it to `block` with
/// revision count `rev`.
pub fn write_compaction(
    dev: &mut dyn BlockDevice,
    geom: &Geom,
    mdir: &Mdir,
    block: u32,
    rev: u32,
) -> Result<()> {
    let mut c = CommitBuf::new(rev);
    for (id, e) in mdir.entries.iter().enumerate() {
        let id = id as u16;
        // The name tag must come first for an id; everything else hangs
        // off it.
        c.push(
            Tag::new(tag::TYPE_NAME | e.kind as u16, id, e.name.len() as u16),
            &e.name,
        );
        match &e.data {
            Some(Struct::Dir(p)) => {
                let mut d = [0u8; 8];
                d[0..4].copy_from_slice(&p[0].to_le_bytes());
                d[4..8].copy_from_slice(&p[1].to_le_bytes());
                c.push(Tag::new(tag::TYPE_DIRSTRUCT, id, 8), &d);
            }
            Some(Struct::Ctz { head, size }) => {
                let mut d = [0u8; 8];
                d[0..4].copy_from_slice(&head.to_le_bytes());
                d[4..8].copy_from_slice(&size.to_le_bytes());
                c.push(Tag::new(tag::TYPE_CTZSTRUCT, id, 8), &d);
            }
            Some(Struct::Inline(data)) => {
                c.push(
                    Tag::new(tag::TYPE_INLINESTRUCT, id, data.len() as u16),
                    data,
                );
            }
            None => {}
        }
        for (k, v) in &e.attrs {
            c.push(
                Tag::new(tag::TYPE_USERATTR | *k as u16, id, v.len() as u16),
                v,
            );
        }
    }
    if let Some(t) = mdir.tail {
        let mut d = [0u8; 8];
        d[0..4].copy_from_slice(&t[0].to_le_bytes());
        d[4..8].copy_from_slice(&t[1].to_le_bytes());
        let ty = if mdir.hard {
            tag::TYPE_HARDTAIL
        } else {
            tag::TYPE_SOFTTAIL
        };
        c.push(Tag::new(ty, tag::ID_NONE, 8), &d);
    }
    if let Some(g) = mdir.gdelta {
        c.push(Tag::new(tag::TYPE_MOVESTATE, tag::ID_NONE, 12), &g);
    }

    let image = c.finish(geom)?;
    dev.write_at(geom.offset(block), &image)
}

/// Whether `mdir`'s contents still fit one metadata block, or need to be
/// split across two pairs first. Measured the same way [`split_point`]
/// measures its candidates, so the two can never disagree about whether a
/// given set of entries fits.
pub fn needs_split(geom: &Geom, mdir: &Mdir) -> bool {
    // littlefs also caps a pair at 0xff ids, halving the split point until
    // both bounds hold.
    mdir.entries_size() > geom.split_limit() || mdir.entries.len() >= 0xff
}

/// Pick how many leading entries stay in the pair when splitting, mirroring
/// littlefs's "halve until it fits" search. Returns `0` when even a single
/// entry is too large for a block — the caller turns that into an error.
pub fn split_point(geom: &Geom, mdir: &Mdir) -> usize {
    let end = mdir.entries.len();
    let mut split = 0usize;
    while end - split > 1 {
        let size: usize = mdir.entries[split..end]
            .iter()
            .map(Entry::commit_size)
            .sum();
        if end - split < 0xff && size <= geom.split_limit() {
            break;
        }
        split += (end - split) / 2;
    }
    split
}
