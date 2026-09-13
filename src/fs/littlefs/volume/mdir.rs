//! Metadata pairs, read in place and written by streaming.
//!
//! The hosted half replays a pair's log into a `Vec<Entry>` and works on
//! that. With no heap there is nowhere to put such a view, so this module
//! does what the C implementation does instead: it keeps the live block's
//! bytes in the volume's single block of scratch and answers every question
//! by walking the tag log.
//!
//! Two walks carry everything:
//!
//! * [`parse`] replays the log forward, promoting its state at each valid
//!   commit CRC, and ends up with what the pair *is* — revision count, how
//!   many file ids it holds, its tail pointer, its global-state delta, and
//!   where the last good commit ended. Tags themselves are not kept.
//! * [`get`] walks the log **backwards** from there, which the tag chain
//!   allows because each stored word is XORed with the previous tag. The
//!   first tag matching the query is by construction the newest one, and
//!   the splice tags passed on the way back say how the id being looked for
//!   was numbered at that point in the log. This is `lfs_dir_getslice`.
//!
//! Writing goes the other way: [`Commit`] appends tags into a staging
//! buffer the size of one program page and programs each page as it fills,
//! so a whole commit is never held in RAM. What it emits is a *compaction* —
//! the pair's entire state written fresh into its stale block — which is the
//! same operation littlefs performs when a metadata block fills up, so the
//! result is always a volume a stock littlefs can mount and keep appending
//! to.

use super::super::tag::{self, Tag};
use super::{Error, FlashDriver, Geometry};

/// Tag-field mask matching a tag's abstract type (type1) and its id.
const MASK_TYPE1_ID: u32 = ((0x700u32) << 20) | (0x3ffu32 << 10);
/// Tag-field mask matching a tag's full type and its id.
const MASK_TYPE3_ID: u32 = ((0x7ffu32) << 20) | (0x3ffu32 << 10);
/// Just the id field.
const MASK_ID: u32 = 0x3ffu32 << 10;

/// A metadata pair as the log says it stands.
///
/// Everything here is a fixed-size scalar: the entries themselves stay on
/// the device (or, for the live block, in the volume's scratch buffer) and
/// are read through [`get`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Mdir {
    /// The pair's blocks, live one first.
    pub pair: [u32; 2],
    /// Revision count of the live block.
    pub rev: u32,
    /// Offset one past the end of the last valid commit.
    pub off: u32,
    /// The XOR state at that point — the last tag of the commit. Walking
    /// the log backwards starts here.
    pub etag: u32,
    /// Number of file ids the pair holds.
    pub count: u16,
    /// Next metadata pair in the threaded list, if any.
    pub tail: Option<[u32; 2]>,
    /// Whether `tail` is a *hard* tail — the continuation of this same
    /// directory — rather than a soft one that merely threads the list.
    pub hard: bool,
    /// Global-state delta carried by this pair, preserved verbatim. The
    /// filesystem's global state is the XOR of every pair's delta, so a
    /// rewrite that dropped it would corrupt the sum.
    pub gdelta: Option<[u8; 12]>,
}

impl Mdir {
    /// An empty pair, not yet written to disk.
    pub fn empty(pair: [u32; 2]) -> Self {
        Self {
            pair,
            rev: 0,
            off: 0,
            etag: tag::PTAG_INIT,
            count: 0,
            tail: None,
            hard: false,
            gdelta: None,
        }
    }

    /// The pair's stale block — the one a compaction is written into.
    pub fn target(&self) -> u32 {
        self.pair[1]
    }
}

/// The on-disk structure attached to a file id. `Inline` points into the
/// block the pair was parsed from rather than owning its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Struct {
    /// Directory: pointer to the first metadata pair of the directory.
    Dir([u32; 2]),
    /// Small file stored directly in the metadata block, at `off` for `len`
    /// bytes.
    Inline { off: u32, len: u32 },
    /// File stored as a CTZ skip-list rooted at `head`.
    Ctz { head: u32, size: u32 },
}

impl Struct {
    /// Bytes a commit spends on this struct's tag and data.
    fn commit_size(&self) -> usize {
        match self {
            Struct::Dir(_) | Struct::Ctz { .. } => 4 + 8,
            Struct::Inline { len, .. } => 4 + *len as usize,
        }
    }
}

/// Replay one block's commits.
///
/// Returns `None` when the block holds no valid commit at all, otherwise
/// the state as of its last valid one. `buf` must be the block's contents
/// and `pair` the pair it belongs to, live block first.
pub(super) fn parse(buf: &[u8], pair: [u32; 2]) -> Option<Mdir> {
    let bs = buf.len();
    if bs < 8 {
        return None;
    }
    let rev = tag::le32(&buf[0..4]);
    let mut live: Option<Mdir> = None;
    let mut cur = Mdir {
        rev,
        ..Mdir::empty(pair)
    };

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
            if off + 8 > bs || crc != tag::le32(&buf[off + 4..off + 8]) {
                break;
            }
            // The CRC tag's low chunk bit flips the valid-bit state the next
            // commit's tags are expected to have.
            ptag ^= ((t.chunk() & 1) as u32) << 31;
            live = Some(Mdir {
                off: (off + t.dsize()) as u32,
                etag: ptag,
                ..cur
            });
            crc = tag::PTAG_INIT;
            continue;
        }

        let data = &buf[off + 4..off + t.dsize()];
        crc = tag::crc(crc, data);
        apply(&mut cur, t, data);
    }

    live
}

/// Fold one tag into the running state. Only the pair-level facts are
/// tracked; per-id data is left where it lies, for [`get`] to find.
fn apply(m: &mut Mdir, t: Tag, data: &[u8]) {
    match t.type1() {
        tag::T1_SPLICE => {
            // A create inserts an id (shifting later ids up), a delete
            // removes one (shifting them down).
            match t.type3() {
                tag::TYPE_CREATE => m.count = m.count.saturating_add(1),
                tag::TYPE_DELETE => m.count = m.count.saturating_sub(1),
                _ => {}
            }
        }
        tag::T1_TAIL => {
            if data.len() >= 8 {
                m.tail = Some([tag::le32(&data[0..4]), tag::le32(&data[4..8])]);
                m.hard = t.chunk() & 1 != 0;
            }
        }
        tag::T1_GSTATE => {
            if data.len() >= 12 {
                let mut g = [0u8; 12];
                g.copy_from_slice(&data[..12]);
                m.gdelta = Some(g);
            }
        }
        // A name, struct or attribute tag for an id past the current count
        // implicitly makes room for it, as it does in littlefs.
        tag::T1_NAME | tag::T1_STRUCT | tag::T1_USERATTR => {
            let id = t.id();
            if id < tag::ID_NONE && id + 1 > m.count {
                m.count = id + 1;
            }
        }
        _ => {}
    }
}

/// The newest tag matching `want` under `mask`, and where its data starts.
///
/// `buf` must be the live block's contents. The search runs backwards from
/// the end of the last valid commit, so tags a later commit superseded are
/// never seen; splices met on the way tell how the sought id was numbered
/// further back in the log. A tag that marks its attribute deleted, or an
/// id whose creation is reached, reports `None`.
///
/// This is `lfs_dir_getslice`, minus the synthetic-move handling: nothing
/// here creates a move, and an image interrupted mid-move by a stock
/// littlefs is read the way the hosted half reads it.
pub(super) fn get(buf: &[u8], m: &Mdir, mask: u32, want: u32) -> Option<(Tag, u32)> {
    let bs = buf.len();
    if m.off as usize > bs {
        return None;
    }
    let mut off = m.off as usize;
    let mut ntag = m.etag;
    // How far the sought id has drifted between the end of the log and
    // where the walk currently is, in id units.
    let mut diff: i32 = 0;
    let by_id = mask & MASK_ID != 0;

    loop {
        let dsize = Tag(ntag).dsize();
        if off < 4 + dsize {
            return None;
        }
        off -= dsize;
        let t = Tag(ntag);
        // Each stored word is the tag XORed with its predecessor, which is
        // what makes the log walkable in this direction.
        ntag = (tag::be32(&buf[off..off + 4]) ^ t.0) & 0x7fff_ffff;

        let sought = want.wrapping_add((diff as u32) << 10);
        if by_id && t.type1() == tag::T1_SPLICE && t.id() <= Tag(sought).id() {
            if t.0 == (Tag::new(tag::TYPE_CREATE, 0, 0).0 | (MASK_ID & sought)) {
                // Walked back past the creation of the id being sought: it
                // did not exist here yet.
                return None;
            }
            // Step the sought id around the splice.
            diff -= match t.type3() {
                tag::TYPE_CREATE => 1,
                tag::TYPE_DELETE => -1,
                _ => 0,
            };
            continue;
        }

        if mask & t.0 == mask & sought {
            if t.is_delete() {
                return None;
            }
            if off + t.dsize() > bs {
                return None;
            }
            // Report the tag with its id in the *current* numbering: `diff`
            // is how far back the walk has drifted, so undoing it maps the
            // id forward again. The field is replaced rather than added to,
            // which would borrow straight into the type.
            let id = (t.id() as i32 - diff) as u32 & 0x3ff;
            return Some((Tag((t.0 & !MASK_ID) | (id << 10)), (off + 4) as u32));
        }
    }
}

/// The name tag of `id`: its kind (`TYPE_REG`, `TYPE_DIR`, `TYPE_SUPERBLOCK`)
/// and where the name lies in `buf`.
pub(super) fn name_of(buf: &[u8], m: &Mdir, id: u16) -> Option<(u8, u32, u32)> {
    let (t, off) = get(buf, m, MASK_TYPE1_ID, Tag::new(tag::TYPE_NAME, id, 0).0)?;
    Some((t.chunk(), off, t.size() as u32))
}

/// The struct tag of `id`, decoded.
pub(super) fn struct_of(buf: &[u8], m: &Mdir, id: u16) -> Option<Struct> {
    let (t, off) = get(
        buf,
        m,
        MASK_TYPE1_ID,
        Tag::new(tag::TYPE_DIRSTRUCT, id, 0).0,
    )?;
    let data = buf.get(off as usize..off as usize + t.size() as usize)?;
    match t.type3() {
        tag::TYPE_DIRSTRUCT if data.len() >= 8 => Some(Struct::Dir([
            tag::le32(&data[0..4]),
            tag::le32(&data[4..8]),
        ])),
        tag::TYPE_CTZSTRUCT if data.len() >= 8 => Some(Struct::Ctz {
            head: tag::le32(&data[0..4]),
            size: tag::le32(&data[4..8]),
        }),
        tag::TYPE_INLINESTRUCT => Some(Struct::Inline {
            off,
            len: data.len() as u32,
        }),
        _ => None,
    }
}

/// One user attribute of `id`: where its value lies in `buf`.
pub(super) fn attr_of(buf: &[u8], m: &Mdir, id: u16, key: u8) -> Option<(u32, u32)> {
    let (t, off) = get(
        buf,
        m,
        MASK_TYPE3_ID,
        Tag::new(tag::TYPE_USERATTR | key as u16, id, 0).0,
    )?;
    Some((off, t.size() as u32))
}

/// Which attribute keys the pair mentions anywhere, as a 256-bit map.
///
/// A superset: a key here may belong to another id, or have been deleted
/// since. It exists so that copying an id's attributes forward costs one
/// [`get`] per key that could possibly apply rather than 256 of them, and
/// nothing at all on the overwhelmingly common pair that has no attributes.
pub(super) fn attr_keys(buf: &[u8], m: &Mdir) -> [u32; 8] {
    let mut keys = [0u32; 8];
    let bs = buf.len();
    let mut off = 0usize;
    let mut ptag = tag::PTAG_INIT;
    let end = m.off as usize;
    loop {
        off += Tag(ptag).dsize();
        if off + 4 > bs || off >= end {
            return keys;
        }
        let t = Tag(tag::be32(&buf[off..off + 4]) ^ ptag);
        if !t.is_valid() || off + t.dsize() > bs {
            return keys;
        }
        ptag = t.0;
        if t.type2() == tag::TYPE_CCRC {
            ptag ^= ((t.chunk() & 1) as u32) << 31;
            continue;
        }
        if t.type1() == tag::T1_USERATTR {
            let key = t.chunk();
            keys[key as usize / 32] |= 1 << (key % 32);
        }
    }
}

/// Whether `keys` holds anything at all.
pub(super) fn no_attrs(keys: &[u32; 8]) -> bool {
    keys.iter().all(|w| *w == 0)
}

/// Whether `key` is set in `keys`.
pub(super) fn has_key(keys: &[u32; 8], key: u8) -> bool {
    keys[key as usize / 32] & (1 << (key % 32)) != 0
}

// ---------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------

/// Where a tag's data comes from when a commit is written.
#[derive(Debug, Clone, Copy)]
pub(super) enum Data<'a> {
    /// Bytes the caller supplied.
    Bytes(&'a [u8]),
    /// A run of the source block — an entry being copied forward.
    Run { off: u32, len: u32 },
    /// Inline file contents being edited: the source run `old`, with `new`
    /// written at offset `at`, zero-filled out to `len` bytes.
    Patch {
        old: (u32, u32),
        at: u32,
        new: &'a [u8],
        len: u32,
    },
}

impl Data<'_> {
    /// Length of the data this will emit.
    pub fn len(&self) -> u32 {
        match self {
            Data::Bytes(b) => b.len() as u32,
            Data::Run { len, .. } => *len,
            Data::Patch { len, .. } => *len,
        }
    }

    /// The byte at `at`, or `None` past the end.
    fn byte(&self, src: &[u8], at: u32) -> Option<u8> {
        match self {
            Data::Bytes(b) => b.get(at as usize).copied(),
            Data::Run { off, len } => {
                if at >= *len {
                    return None;
                }
                src.get((off + at) as usize).copied()
            }
            Data::Patch {
                old,
                at: patch_at,
                new,
                len,
            } => {
                if at >= *len {
                    return None;
                }
                if at >= *patch_at && at - *patch_at < new.len() as u32 {
                    return new.get((at - *patch_at) as usize).copied();
                }
                if at < old.1 {
                    return src.get((old.0 + at) as usize).copied();
                }
                // A gap left by a write past the end of the file.
                Some(0)
            }
        }
    }
}

/// The struct a commit should write for an id.
#[derive(Debug, Clone, Copy)]
pub(super) enum StructOut<'a> {
    /// Directory pointer.
    Dir([u32; 2]),
    /// CTZ skip-list.
    Ctz { head: u32, size: u32 },
    /// Inline data, from anywhere [`Data`] can name.
    Inline(Data<'a>),
}

/// One commit in progress: tags are pushed in, whole program pages leave
/// for the device as they fill, and [`Commit::finish`] closes the log with
/// the forward CRC and the commit CRC.
///
/// The fields are borrowed rather than reached through a `&mut Volume`
/// because a commit reads the source block out of the volume's scratch
/// while programming the target one — two disjoint fields of the same
/// struct.
pub(super) struct Commit<'a, D: FlashDriver> {
    dev: &'a mut D,
    /// Staging buffer; `chunk` bytes of it are used.
    stage: &'a mut [u8],
    chunk: usize,
    staged: usize,
    /// Offset in the block the staged bytes start at.
    base: u32,
    block: u32,
    block_size: u32,
    prog_size: u32,
    crc: u32,
    ptag: u32,
}

impl<'a, D: FlashDriver> Commit<'a, D> {
    /// Start a commit at the beginning of `block`, which the caller has
    /// erased. `rev` is the revision count it opens with.
    pub fn new(
        dev: &'a mut D,
        stage: &'a mut [u8],
        geom: &Geometry,
        block: u32,
        rev: u32,
    ) -> Result<Self, Error<D::Error>> {
        let prog = geom.prog_size.max(1) as usize;
        // Program pages are the unit the device takes, so stage a whole
        // number of them.
        let chunk = (stage.len() / prog) * prog;
        let mut c = Self {
            dev,
            stage,
            chunk,
            staged: 0,
            base: 0,
            block,
            block_size: geom.block_size,
            prog_size: geom.prog_size.max(1),
            crc: tag::PTAG_INIT,
            ptag: tag::PTAG_INIT,
        };
        c.push_bytes(&rev.to_le_bytes())?;
        Ok(c)
    }

    /// Bytes written into the block so far.
    fn off(&self) -> u32 {
        self.base + self.staged as u32
    }

    /// Stage `data`, programming pages as they fill. The running CRC is
    /// updated by the callers, which know what belongs in it.
    fn stage_bytes(&mut self, data: &[u8]) -> Result<(), Error<D::Error>> {
        let mut at = 0;
        while at < data.len() {
            if self.staged == self.chunk {
                self.flush_page()?;
            }
            let n = (self.chunk - self.staged).min(data.len() - at);
            self.stage[self.staged..self.staged + n].copy_from_slice(&data[at..at + n]);
            self.staged += n;
            at += n;
        }
        Ok(())
    }

    /// Program the staged pages out.
    fn flush_page(&mut self) -> Result<(), Error<D::Error>> {
        if self.staged == 0 {
            return Ok(());
        }
        // Only whole pages may leave; a partial tail waits for `finish`.
        let whole = (self.staged / self.prog_size as usize) * self.prog_size as usize;
        if whole == 0 {
            return Err(Error::ScratchTooSmall {
                needed: self.prog_size as usize,
                got: self.stage.len(),
            });
        }
        self.dev
            .prog(self.block, self.base, &self.stage[..whole])
            .map_err(Error::Io)?;
        self.stage.copy_within(whole..self.staged, 0);
        self.staged -= whole;
        self.base += whole as u32;
        Ok(())
    }

    /// Append bytes that are part of the commit's checksum.
    fn push_bytes(&mut self, data: &[u8]) -> Result<(), Error<D::Error>> {
        self.crc = tag::crc(self.crc, data);
        self.stage_bytes(data)
    }

    /// Append one tag and its data, which may come from the source block.
    pub fn push(&mut self, t: Tag, data: &Data<'_>, src: &[u8]) -> Result<(), Error<D::Error>> {
        let stored = (t.0 & 0x7fff_ffff) ^ self.ptag;
        self.push_bytes(&stored.to_be_bytes())?;
        self.ptag = t.0 & 0x7fff_ffff;
        if t.is_delete() {
            return Ok(());
        }
        // Copied a chunk at a time so an inline file the size of a tag's
        // payload never needs a buffer of its own.
        let mut tmp = [0u8; 64];
        let total = data.len();
        let mut at = 0;
        while at < total {
            let n = (total - at).min(tmp.len() as u32) as usize;
            for (i, slot) in tmp[..n].iter_mut().enumerate() {
                *slot = data.byte(src, at + i as u32).unwrap_or(0);
            }
            self.push_bytes(&tmp[..n])?;
            at += n as u32;
        }
        Ok(())
    }

    /// Append a tag whose data is a fixed little-endian pair of words.
    pub fn push_pair(&mut self, t: Tag, words: [u32; 2]) -> Result<(), Error<D::Error>> {
        let mut d = [0u8; 8];
        d[0..4].copy_from_slice(&words[0].to_le_bytes());
        d[4..8].copy_from_slice(&words[1].to_le_bytes());
        self.push(t, &Data::Bytes(&d), &[])
    }

    /// Close the commit: the optional forward CRC, the commit CRC tag with
    /// its padding, and the final partial page.
    ///
    /// Everything after the commit stays in the erased state (`0xff`), which
    /// is what lets a real littlefs append its next commit here in place.
    /// That is also what the forward CRC records: the checksum of the erased
    /// window that follows, proving to the next mount that nothing was
    /// half-programmed into it.
    pub fn finish(mut self, fcrc: bool) -> Result<u32, Error<D::Error>> {
        let bs = self.block_size;
        let prog = self.prog_size;

        // Room for the FCRC (tag + 8) plus the CRC tag (tag + 4), matching
        // the 5-word window littlefs reserves.
        let reserve = if fcrc { 5 * 4 } else { 2 * 4 };
        if self.off() + reserve > bs {
            return Err(Error::CommitTooLarge);
        }
        let end = (self.off() + reserve).next_multiple_of(prog);
        if end > bs {
            return Err(Error::CommitTooLarge);
        }

        if fcrc && end <= bs - prog {
            // The window is erased, so its checksum needs no read.
            let erased = [0xffu8; 64];
            let mut fc = tag::PTAG_INIT;
            let mut left = prog as usize;
            while left > 0 {
                let n = left.min(erased.len());
                fc = tag::crc(fc, &erased[..n]);
                left -= n;
            }
            let mut d = [0u8; 8];
            d[0..4].copy_from_slice(&prog.to_le_bytes());
            d[4..8].copy_from_slice(&fc.to_le_bytes());
            self.push(
                Tag::new(tag::TYPE_FCRC, tag::ID_NONE, 8),
                &Data::Bytes(&d),
                &[],
            )?;
        }

        // The CRC tag's size field covers the padding up to `end`, so a
        // fetch can skip straight over it. The low chunk bit is chosen so
        // that reading the erased byte at `end` yields an *invalid* tag,
        // which is how the next mount recognises unwritten storage; over
        // erased storage that bit is always clear.
        let pad = end - (self.off() + 4);
        if pad as usize > tag::MAX_SIZE {
            return Err(Error::CommitTooLarge);
        }
        let ccrc = Tag::new(tag::TYPE_CCRC, tag::ID_NONE, pad as u16);
        let stored = (ccrc.0 & 0x7fff_ffff) ^ self.ptag;
        self.push_bytes(&stored.to_be_bytes())?;

        let crc = self.crc;
        // The checksum itself is not part of what it covers.
        self.stage_bytes(&crc.to_le_bytes())?;
        // The padding is left erased, so the final page is padded with the
        // erased value rather than zeros.
        let written = self.off();
        if written < end {
            let fill = [0xffu8; 64];
            let mut left = (end - written) as usize;
            while left > 0 {
                let n = left.min(fill.len());
                self.stage_bytes(&fill[..n])?;
                left -= n;
            }
        }
        debug_assert_eq!(self.off(), end);
        // A final partial page cannot happen — `end` is a multiple of the
        // program size — but a staging buffer that is not is handled by
        // programming what is left.
        let staged = self.staged;
        if staged > 0 {
            self.dev
                .prog(self.block, self.base, &self.stage[..staged])
                .map_err(Error::Io)?;
            self.base += staged as u32;
            self.staged = 0;
        }
        Ok(end)
    }
}

/// Size of a struct as stored, for entries copied forward unchanged.
pub(super) fn struct_size(s: &Struct) -> usize {
    s.commit_size()
}

/// Size a struct a caller is writing will take.
pub(super) fn struct_out_size(s: &StructOut<'_>) -> usize {
    match s {
        StructOut::Dir(_) | StructOut::Ctz { .. } => 4 + 8,
        StructOut::Inline(d) => 4 + d.len() as usize,
    }
}
