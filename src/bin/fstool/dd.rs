//! `fstool dd` — resilient raw block copy from one file/device to another.
//!
//! Unlike `convert` / `repack` this is **container-agnostic**: it copies raw
//! bytes (a qcow2 file is cloned as-is), so it opens the source and
//! destination as plain [`FileBackend`]s rather than going through the
//! format-detecting [`fstool::block::open_image`].
//!
//! Two design goals beyond a plain copy:
//!
//! - **Error resilience.** Reads start at the largest block (default 1 MiB)
//!   and, on a read error, the block is halved and retried at the same offset
//!   down to the source's smallest sector. A smallest-block read that still
//!   fails is *skipped* (left sparse on the destination) and recorded — the
//!   copy continues instead of aborting. This is the `ddrescue` model.
//! - **Live feedback.** A reader thread and a writer thread are joined by a
//!   bounded buffer pool, so the progress line can show separate read/write
//!   throughput and the pipeline's buffer occupancy alongside the usual bar,
//!   percentage, ETA, current block size, and bytes skipped.
//!
//! Ctrl-C cancels a running copy cleanly (a SIGINT handler sets a flag the
//! reader polls); the threads drain, and the final summary reports how far
//! the copy got.

use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use fstool::block::file::is_block_device;
use fstool::block::{BlockDevice, FileBackend};
use fstool::{Error, Result};

/// Set by the SIGINT handler; polled by the reader so Ctrl-C cancels a copy
/// without killing the process mid-write.
static INTERRUPT: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn handle_sigint(_sig: libc::c_int) {
    INTERRUPT.store(true, Ordering::SeqCst);
}

/// Install the SIGINT → flag handler exactly once (unix only; a no-op
/// elsewhere, where Ctrl-C keeps its default terminate behaviour).
fn install_interrupt_handler() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        #[cfg(unix)]
        // SAFETY: the handler only performs an atomic store, which is
        // async-signal-safe.
        unsafe {
            libc::signal(
                libc::SIGINT,
                handle_sigint as *const () as libc::sighandler_t,
            );
        }
    });
}

fn interrupted() -> bool {
    INTERRUPT.load(Ordering::Relaxed)
}

/// Parsed `dd` arguments, borrowed from the clap-parsed `Command::Dd`.
pub struct DdArgs<'a> {
    pub src: &'a Path,
    pub dst: &'a Path,
    pub block_size: &'a str,
    pub min_block_size: Option<&'a str>,
    pub queue: usize,
    pub force: bool,
    pub no_progress: bool,
}

/// A unit of good data the reader hands to the writer.
struct Job {
    offset: u64,
    buf: Vec<u8>,
}

/// Live counters shared between the reader, writer, and progress renderer.
#[derive(Default)]
struct Shared {
    /// Bytes of the source consumed so far (good + skipped).
    read_pos: AtomicU64,
    /// Bytes actually written to the destination.
    written: AtomicU64,
    /// Bytes skipped because they were unreadable.
    bad_bytes: AtomicU64,
    /// Number of distinct skipped (bad) ranges.
    bad_ranges: AtomicU64,
    /// Current read block size, in bytes (drops on error, ramps back up).
    cur_block: AtomicU64,
    /// Buffers handed to the writer but not yet returned to the pool.
    inflight: AtomicUsize,
}

/// Outcome of one adaptive read attempt at a given offset.
enum ReadOutcome {
    /// `n` bytes were read successfully into the buffer.
    Good(usize),
    /// `n` bytes could not be read and should be skipped.
    Bad(usize),
}

/// Read up to `max_block` bytes at `pos`, halving the block on error down to
/// `min_block`. Returns [`ReadOutcome::Good`] with the bytes read (left in
/// `buf`), or [`ReadOutcome::Bad`] when even a `min_block` read fails (the
/// caller skips that span). `buf` is resized to the attempted length.
fn adaptive_read(
    dev: &mut dyn BlockDevice,
    pos: u64,
    end: u64,
    max_block: usize,
    min_block: usize,
    buf: &mut Vec<u8>,
    cur_block: &AtomicU64,
) -> ReadOutcome {
    let mut try_len = (max_block as u64).min(end - pos) as usize;
    loop {
        buf.resize(try_len, 0);
        match dev.read_at(pos, &mut buf[..try_len]) {
            Ok(()) => return ReadOutcome::Good(try_len),
            Err(_) => {
                if try_len <= min_block {
                    return ReadOutcome::Bad(try_len);
                }
                try_len = (try_len / 2).max(min_block);
                cur_block.store(try_len as u64, Ordering::Relaxed);
            }
        }
    }
}

/// The reader half of the pipeline: walk `[0, total)` with [`adaptive_read`],
/// sending good chunks to the writer and skipping unreadable ones. Reuses a
/// single buffer across skips so the pool's only producer is the writer (that
/// keeps `free_rx.recv()` erroring out when the writer dies — clean teardown).
fn reader(
    mut src: Box<dyn BlockDevice>,
    total: u64,
    max_block: usize,
    min_block: usize,
    job_tx: mpsc::Sender<Job>,
    free_rx: mpsc::Receiver<Vec<u8>>,
    sh: Arc<Shared>,
) -> Result<()> {
    let mut pos = 0u64;
    let mut spare: Option<Vec<u8>> = None;
    while pos < total {
        if interrupted() {
            break;
        }
        let mut buf = match spare.take() {
            Some(b) => b,
            None => match free_rx.recv() {
                Ok(b) => b,
                Err(_) => break, // writer gone
            },
        };
        sh.cur_block
            .store((max_block as u64).min(total - pos), Ordering::Relaxed);
        match adaptive_read(
            src.as_mut(),
            pos,
            total,
            max_block,
            min_block,
            &mut buf,
            &sh.cur_block,
        ) {
            ReadOutcome::Good(n) => {
                let offset = pos;
                pos += n as u64;
                sh.read_pos.store(pos, Ordering::Relaxed);
                sh.inflight.fetch_add(1, Ordering::Relaxed);
                if job_tx.send(Job { offset, buf }).is_err() {
                    sh.inflight.fetch_sub(1, Ordering::Relaxed);
                    break; // writer gone
                }
            }
            ReadOutcome::Bad(n) => {
                pos += n as u64;
                sh.read_pos.store(pos, Ordering::Relaxed);
                sh.bad_bytes.fetch_add(n as u64, Ordering::Relaxed);
                sh.bad_ranges.fetch_add(1, Ordering::Relaxed);
                spare = Some(buf); // reuse this buffer next iteration
            }
        }
    }
    Ok(())
}

/// The writer half: receive good chunks and write them at their offset,
/// returning each buffer to the pool. When `sparse_zeros` is set (a freshly
/// created regular-file destination), all-zero chunks are not written so the
/// output stays sparse. Returns the destination device so callers (and tests)
/// can recover or inspect it after the copy.
fn writer(
    mut dst: Box<dyn BlockDevice>,
    sparse_zeros: bool,
    job_rx: mpsc::Receiver<Job>,
    free_tx: mpsc::Sender<Vec<u8>>,
    sh: Arc<Shared>,
) -> Result<Box<dyn BlockDevice>> {
    while let Ok(Job { offset, buf }) = job_rx.recv() {
        if !(sparse_zeros && buf.iter().all(|&b| b == 0)) {
            dst.write_at(offset, &buf)?;
        }
        sh.written.fetch_add(buf.len() as u64, Ordering::Relaxed);
        sh.inflight.fetch_sub(1, Ordering::Relaxed);
        let _ = free_tx.send(buf); // return to pool (ignore if reader gone)
    }
    dst.sync()?;
    Ok(dst)
}

/// Final tally of a copy.
struct Stats {
    copied: u64,
    written: u64,
    bad_bytes: u64,
    bad_ranges: u64,
    interrupted: bool,
    elapsed: Duration,
}

/// A configured copy ready to run. Owns both devices (they move into the
/// reader/writer threads).
struct Copy {
    src: Box<dyn BlockDevice>,
    dst: Box<dyn BlockDevice>,
    total: u64,
    max_block: usize,
    min_block: usize,
    queue: usize,
    sparse_zeros: bool,
    show: bool,
}

impl Copy {
    /// Run the pipeline to completion, returning the tally and the
    /// destination device (recovered from the writer thread).
    fn run(self) -> Result<(Stats, Box<dyn BlockDevice>)> {
        let sh = Arc::new(Shared::default());
        sh.cur_block.store(self.max_block as u64, Ordering::Relaxed);

        let (job_tx, job_rx) = mpsc::channel::<Job>();
        let (free_tx, free_rx) = mpsc::channel::<Vec<u8>>();
        // Seed the pool. The writer holds the only `free_tx`, so once it ends
        // the reader's `free_rx.recv()` errors and the reader stops too.
        for _ in 0..self.queue {
            free_tx
                .send(vec![0u8; self.max_block])
                .expect("free_rx is alive");
        }

        let start = Instant::now();
        let (total, max_block, min_block) = (self.total, self.max_block, self.min_block);
        let (queue, sparse_zeros, show) = (self.queue, self.sparse_zeros, self.show);
        let (src, dst) = (self.src, self.dst);

        let rsh = Arc::clone(&sh);
        let reader_h =
            thread::spawn(move || reader(src, total, max_block, min_block, job_tx, free_rx, rsh));
        let wsh = Arc::clone(&sh);
        let writer_h = thread::spawn(move || writer(dst, sparse_zeros, job_rx, free_tx, wsh));

        if show {
            let mut last = Instant::now();
            let (mut last_rd, mut last_wr) = (0u64, 0u64);
            loop {
                thread::sleep(Duration::from_millis(150));
                let done = reader_h.is_finished() && writer_h.is_finished();
                let now = Instant::now();
                let dt = (now - last).as_secs_f64().max(1e-6);
                let rd = sh.read_pos.load(Ordering::Relaxed);
                let wr = sh.written.load(Ordering::Relaxed);
                let rd_rate = rd.saturating_sub(last_rd) as f64 / dt;
                let wr_rate = wr.saturating_sub(last_wr) as f64 / dt;
                render_progress(&sh, total, queue, rd, wr, rd_rate, wr_rate);
                last = now;
                (last_rd, last_wr) = (rd, wr);
                if done {
                    break;
                }
            }
            eprintln!(); // end the \r line
        }

        let reader_res = reader_h
            .join()
            .map_err(|_| Error::InvalidArgument("dd: reader thread panicked".into()))?;
        let writer_res = writer_h
            .join()
            .map_err(|_| Error::InvalidArgument("dd: writer thread panicked".into()))?;
        reader_res?;
        let dst = writer_res?;

        let stats = Stats {
            copied: sh.read_pos.load(Ordering::Relaxed),
            written: sh.written.load(Ordering::Relaxed),
            bad_bytes: sh.bad_bytes.load(Ordering::Relaxed),
            bad_ranges: sh.bad_ranges.load(Ordering::Relaxed),
            interrupted: interrupted(),
            elapsed: start.elapsed(),
        };
        Ok((stats, dst))
    }
}

/// Render the single live progress line to stderr (carriage-return, no
/// newline). Padded so a shrinking line doesn't leave stale characters.
fn render_progress(
    sh: &Shared,
    total: u64,
    queue: usize,
    rd: u64,
    wr: u64,
    rd_rate: f64,
    wr_rate: f64,
) {
    let frac = if total == 0 {
        1.0
    } else {
        (rd as f64 / total as f64).clamp(0.0, 1.0)
    };
    let remaining = total.saturating_sub(rd);
    let eta = if wr_rate > 1.0 {
        human_dur((remaining as f64 / wr_rate) as u64)
    } else {
        "--:--".to_string()
    };
    let bad = sh.bad_bytes.load(Ordering::Relaxed);
    let blk = sh.cur_block.load(Ordering::Relaxed);
    let inflight = sh.inflight.load(Ordering::Relaxed);
    let line = format!(
        "{:>5.1}% {} {}/{}  rd {}  wr {}  buf {}/{}  blk {}  bad {}  ETA {}",
        frac * 100.0,
        bar(frac, 20),
        human_bytes(rd),
        human_bytes(total),
        human_rate(rd_rate),
        human_rate(wr_rate),
        inflight,
        queue,
        human_bytes(blk),
        human_bytes(bad),
        eta,
    );
    let _ = wr; // wr is folded into wr_rate; kept for signature symmetry
    eprint!("\r{line}    ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
}

/// A `[====>   ]` bar `width` columns wide.
fn bar(frac: f64, width: usize) -> String {
    let filled = ((frac * width as f64) as usize).min(width);
    let mut s = String::with_capacity(width + 2);
    s.push('[');
    for i in 0..width {
        if i < filled {
            // The leading edge shows as `>` until the bar is full.
            if i + 1 == filled && filled < width {
                s.push('>');
            } else {
                s.push('=');
            }
        } else {
            s.push(' ');
        }
    }
    s.push(']');
    s
}

/// Human-readable byte count in binary units (`7.34 GiB`, `8.0 KiB`, `12 B`).
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.2} {}", UNITS[i])
}

/// A byte-rate as `<human_bytes>/s`.
fn human_rate(bytes_per_sec: f64) -> String {
    let n = if bytes_per_sec.is_finite() && bytes_per_sec > 0.0 {
        bytes_per_sec as u64
    } else {
        0
    };
    format!("{}/s", human_bytes(n))
}

/// `H:MM:SS` (hours omitted when zero → `MM:SS`).
fn human_dur(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

/// True when both paths resolve to the same existing file.
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn check_pow2(name: &str, v: usize) -> Result<()> {
    if v == 0 || !v.is_power_of_two() {
        return Err(Error::InvalidArgument(format!(
            "dd: {name} must be a power of two (got {v})"
        )));
    }
    Ok(())
}

/// Entry point for `fstool dd`.
pub fn run(args: DdArgs) -> Result<()> {
    install_interrupt_handler();

    if same_file(args.src, args.dst) {
        return Err(Error::InvalidArgument(
            "dd: source and destination are the same file".into(),
        ));
    }

    let max_block = fstool::spec::parse_size(args.block_size)? as usize;
    check_pow2("--block-size", max_block)?;

    // Source opened raw and read-only — we never modify it.
    let src: Box<dyn BlockDevice> = Box::new(FileBackend::open_read_only(args.src)?);
    let total = src.total_size();
    let min_block = match args.min_block_size {
        Some(s) => fstool::spec::parse_size(s)? as usize,
        None => src.block_size() as usize,
    };
    check_pow2("--min-block-size", min_block)?;
    if min_block > max_block {
        return Err(Error::InvalidArgument(format!(
            "dd: --min-block-size ({min_block}) exceeds --block-size ({max_block})"
        )));
    }

    let dst_is_block = is_block_device(args.dst);
    let dst_exists = args.dst.exists();
    if (dst_is_block || dst_exists) && !args.force {
        return Err(Error::InvalidArgument(format!(
            "dd: {} {}; pass --force to overwrite",
            args.dst.display(),
            if dst_is_block {
                "is a block device"
            } else {
                "already exists"
            }
        )));
    }
    // A freshly created regular file starts all-zero, so we can keep it sparse
    // by not writing all-zero chunks. A block device or pre-existing file is
    // copied faithfully (zeros included) so no stale data survives.
    let sparse_zeros = !dst_is_block && !dst_exists;
    let dst: Box<dyn BlockDevice> = Box::new(FileBackend::create(args.dst, total)?);

    let show = !args.no_progress && std::io::stderr().is_terminal();
    let copy = Copy {
        src,
        dst,
        total,
        max_block,
        min_block,
        queue: args.queue.max(1),
        sparse_zeros,
        show,
    };
    let (stats, _dst) = copy.run()?;

    // Final summary (always printed, even with --no-progress).
    let secs = stats.elapsed.as_secs_f64().max(1e-6);
    let avg = stats.written as f64 / secs;
    let head = if stats.interrupted {
        "dd: interrupted"
    } else {
        "dd: done"
    };
    eprintln!(
        "{head} — copied {} of {} ({} written), {} bad range(s) totalling {}, {} elapsed, avg {}",
        human_bytes(stats.copied),
        human_bytes(total),
        human_bytes(stats.written),
        stats.bad_ranges,
        human_bytes(stats.bad_bytes),
        human_dur(stats.elapsed.as_secs()),
        human_rate(avg),
    );
    if stats.bad_bytes > 0 {
        eprintln!(
            "dd: warning: {} unreadable; those regions were left untouched on the destination",
            human_bytes(stats.bad_bytes),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fstool::block::MemoryBackend;
    use std::io::{self, Read, Seek, SeekFrom, Write};

    /// A [`BlockDevice`] that wraps a [`MemoryBackend`] and fails any read
    /// overlapping `[bad_start, bad_end)`, to exercise the adaptive retry.
    struct ReadFail {
        inner: MemoryBackend,
        bad_start: u64,
        bad_end: u64,
    }

    impl Read for ReadFail {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.inner.read(b)
        }
    }
    impl Write for ReadFail {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.inner.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }
    impl Seek for ReadFail {
        fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
            self.inner.seek(p)
        }
    }
    impl BlockDevice for ReadFail {
        fn block_size(&self) -> u32 {
            self.inner.block_size()
        }
        fn total_size(&self) -> u64 {
            self.inner.total_size()
        }
        fn sync(&mut self) -> Result<()> {
            self.inner.sync()
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
            let end = offset + buf.len() as u64;
            if offset < self.bad_end && self.bad_start < end {
                return Err(Error::Io(io::Error::other("injected read error")));
            }
            self.inner.read_at(offset, buf)
        }
    }

    #[test]
    fn adaptive_read_halves_and_skips() {
        // 512-byte sector 8 (offset 4096) is unreadable.
        let mut mem = MemoryBackend::new(64 * 1024);
        let pattern: Vec<u8> = (0..mem.total_size()).map(|i| (i % 251) as u8).collect();
        mem.write_at(0, &pattern).unwrap();
        let mut dev = ReadFail {
            inner: mem,
            bad_start: 4096,
            bad_end: 4096 + 512,
        };
        let cur = AtomicU64::new(0);
        let mut buf = Vec::new();

        // First 4 KiB reads cleanly at the max block.
        match adaptive_read(&mut dev, 0, 64 * 1024, 4096, 512, &mut buf, &cur) {
            ReadOutcome::Good(n) => assert_eq!(n, 4096),
            ReadOutcome::Bad(_) => panic!("clean region read as bad"),
        }
        // At offset 4096 the 4 KiB read fails and narrows to the bad 512.
        match adaptive_read(&mut dev, 4096, 64 * 1024, 4096, 512, &mut buf, &cur) {
            ReadOutcome::Bad(n) => assert_eq!(n, 512),
            ReadOutcome::Good(_) => panic!("bad sector read as good"),
        }
        assert_eq!(
            cur.load(Ordering::Relaxed),
            512,
            "block should shrink to min"
        );
        // After the bad sector, reads recover.
        match adaptive_read(&mut dev, 4608, 64 * 1024, 4096, 512, &mut buf, &cur) {
            ReadOutcome::Good(n) => assert_eq!(n, 4096),
            ReadOutcome::Bad(_) => panic!("post-bad region read as bad"),
        }
    }

    #[test]
    fn copy_skips_bad_region_and_matches_elsewhere() {
        let size = 64 * 1024u64;
        let mut mem = MemoryBackend::new(size);
        let pattern: Vec<u8> = (0..size).map(|i| ((i % 250) + 1) as u8).collect(); // no zeros
        mem.write_at(0, &pattern).unwrap();
        let src: Box<dyn BlockDevice> = Box::new(ReadFail {
            inner: mem,
            bad_start: 4096,
            bad_end: 4096 + 512,
        });
        let dst: Box<dyn BlockDevice> = Box::new(MemoryBackend::new(size));

        let copy = Copy {
            src,
            dst,
            total: size,
            max_block: 4096,
            min_block: 512,
            queue: 4,
            sparse_zeros: false,
            show: false,
        };
        let (stats, mut dst) = copy.run().unwrap();

        assert_eq!(stats.bad_bytes, 512);
        assert_eq!(stats.bad_ranges, 1);
        assert_eq!(stats.copied, size);

        let mut got = vec![0u8; size as usize];
        dst.read_at(0, &mut got).unwrap();
        // Identical everywhere except the skipped sector, which stays zero.
        let mut expected = pattern.clone();
        for b in &mut expected[4096..4096 + 512] {
            *b = 0;
        }
        assert_eq!(got, expected);
    }

    #[test]
    fn clean_copy_is_identical() {
        let size = 40 * 1024u64;
        let mut mem = MemoryBackend::new(size);
        let pattern: Vec<u8> = (0..size)
            .map(|i| (i.wrapping_mul(31) % 256) as u8)
            .collect();
        mem.write_at(0, &pattern).unwrap();
        let src: Box<dyn BlockDevice> = Box::new(mem);
        let dst: Box<dyn BlockDevice> = Box::new(MemoryBackend::new(size));
        let copy = Copy {
            src,
            dst,
            total: size,
            max_block: 8192,
            min_block: 512,
            queue: 2,
            sparse_zeros: false,
            show: false,
        };
        let (stats, mut dst) = copy.run().unwrap();
        assert_eq!(stats.bad_bytes, 0);
        assert_eq!(stats.written, size);
        let mut got = vec![0u8; size as usize];
        dst.read_at(0, &mut got).unwrap();
        assert_eq!(got, pattern);
    }

    #[test]
    fn human_bytes_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.00 KiB");
        assert_eq!(human_bytes(1536), "1.50 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.00 GiB");
    }

    #[test]
    fn human_dur_formats() {
        assert_eq!(human_dur(45), "00:45");
        assert_eq!(human_dur(605), "10:05");
        assert_eq!(human_dur(3661), "1:01:01");
    }

    #[test]
    fn bar_endpoints() {
        assert_eq!(bar(0.0, 4), "[    ]");
        assert_eq!(bar(1.0, 4), "[====]");
        assert!(bar(0.5, 4).starts_with("[="));
    }
}
