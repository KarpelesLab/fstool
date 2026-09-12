//! Streaming adapter for the LZO codec — LZO1X has no native frame, so we
//! invent a tiny multi-block frame and en/decode each block as a one-shot
//! raw LZO1X block via `compcol::lzo::block`. Every other codec (gzip /
//! zlib / xz / lzma / zstd / lz4) streams natively through `compcol::io`
//! or its one-shot block API (see [`super`]).

#[cfg(feature = "lzo")]
use std::io::{self, Read, Write};

// =============================== lzo ===============================
//
// LZO1X has no native frame format, so we invent a tiny frame: a stream of
// `(u32 LE compressed-len, u32 LE uncompressed-len, payload)` records
// terminated by a `(0, 0)` sentinel, each payload a one-shot raw LZO1X
// block (`compcol::lzo::block`). Records are emitted in 1 MiB chunks. Files
// produced with this framing are NOT interchangeable with any other LZO
// toolchain — they exist only so `make_reader_lzo`'s `Read` impl can
// produce predictable streaming output.

#[cfg(feature = "lzo")]
const LZO_FRAME_CHUNK: usize = 1 << 20;

/// Stream encoder for the fstool LZO frame format described above.
#[cfg(feature = "lzo")]
pub struct LzoFrameWriter<W: Write> {
    inner: Option<W>,
    pending: Vec<u8>,
}

#[cfg(feature = "lzo")]
impl<W: Write> LzoFrameWriter<W> {
    pub fn new(w: W) -> Self {
        Self {
            inner: Some(w),
            pending: Vec::with_capacity(LZO_FRAME_CHUNK),
        }
    }

    fn emit_chunk(&mut self) -> io::Result<()> {
        if self.pending.is_empty() || self.inner.is_none() {
            return Ok(());
        }
        let mut compressed = Vec::new();
        compcol::lzo::block::encode_block(&self.pending, &mut compressed);
        let w = self.inner.as_mut().unwrap();
        w.write_all(&(compressed.len() as u32).to_le_bytes())?;
        w.write_all(&(self.pending.len() as u32).to_le_bytes())?;
        w.write_all(&compressed)?;
        self.pending.clear();
        Ok(())
    }

    /// Emit any buffered data and the end-of-stream sentinel, then
    /// release the sink. Idempotent: a second call does nothing.
    ///
    /// This is deliberately *not* `flush`. `Write::flush` may be called
    /// at any point by a caller that simply wants the bytes so far on
    /// their way — writing the terminator there ends the stream early,
    /// and everything written afterwards sits past a sentinel the
    /// reader stops at.
    fn finish(&mut self) -> io::Result<()> {
        self.emit_chunk()?;
        if let Some(mut w) = self.inner.take() {
            // Sentinel: zero-length chunk header marks end of stream.
            w.write_all(&[0u8; 8])?;
            w.flush()?;
        }
        Ok(())
    }
}

#[cfg(feature = "lzo")]
impl<W: Write> Write for LzoFrameWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let space = LZO_FRAME_CHUNK - self.pending.len();
        let take = buf.len().min(space);
        self.pending.extend_from_slice(&buf[..take]);
        if self.pending.len() == LZO_FRAME_CHUNK {
            self.emit_chunk()?;
        }
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit_chunk()?;
        if let Some(w) = self.inner.as_mut() {
            w.flush()?;
        }
        Ok(())
    }
}

#[cfg(feature = "lzo")]
impl<W: Write> Drop for LzoFrameWriter<W> {
    fn drop(&mut self) {
        // The stream is only ever handed out as a `Box<dyn Write>`, so
        // the terminator has to land here rather than in a public
        // `finish` the caller could reach.
        let _ = self.finish();
    }
}

/// Stream decoder for the fstool LZO frame format.
#[cfg(feature = "lzo")]
pub struct LzoFrameReader<R: Read> {
    inner: R,
    pending: io::Cursor<Vec<u8>>,
    done: bool,
}

#[cfg(feature = "lzo")]
impl<R: Read> LzoFrameReader<R> {
    pub fn new(r: R) -> Self {
        Self {
            inner: r,
            pending: io::Cursor::new(Vec::new()),
            done: false,
        }
    }

    fn fill_next_chunk(&mut self) -> io::Result<()> {
        if self.done {
            return Ok(());
        }
        let mut hdr = [0u8; 8];
        self.inner.read_exact(&mut hdr)?;
        let clen = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
        let ulen = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        if clen == 0 && ulen == 0 {
            self.done = true;
            return Ok(());
        }
        let mut compressed = vec![0u8; clen];
        self.inner.read_exact(&mut compressed)?;
        // `ulen` (the block's declared uncompressed size) caps the decode so a
        // malformed block can't grow the output unbounded.
        let mut out = Vec::new();
        compcol::lzo::block::decode_block(&compressed, &mut out, ulen).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("lzo decode failed: {e}"),
            )
        })?;
        self.pending = io::Cursor::new(out);
        Ok(())
    }
}

#[cfg(feature = "lzo")]
impl<R: Read> Read for LzoFrameReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = self.pending.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            if self.done {
                return Ok(0);
            }
            self.fill_next_chunk()?;
            if self.pending.get_ref().is_empty() && self.done {
                return Ok(0);
            }
        }
    }
}

#[cfg(all(test, feature = "lzo"))]
mod tests {
    use super::*;

    /// `Write::flush` used to emit the end-of-stream sentinel, so a
    /// caller that flushed mid-stream (any buffered sink does) ended the
    /// frame early and everything after it was invisible to the reader.
    #[test]
    fn mid_stream_flush_does_not_terminate() {
        let head = b"first half, before the flush; ".repeat(200);
        let tail = b"second half, after the flush; ".repeat(200);

        let mut out = Vec::new();
        {
            let mut w = LzoFrameWriter::new(&mut out);
            w.write_all(&head).unwrap();
            w.flush().unwrap();
            w.write_all(&tail).unwrap();
        }

        let mut back = Vec::new();
        LzoFrameReader::new(out.as_slice())
            .read_to_end(&mut back)
            .unwrap();
        let mut want = head.clone();
        want.extend_from_slice(&tail);
        assert_eq!(back, want);
    }
}
