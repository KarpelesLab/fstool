//! Interactive shell over an [`fstool::inspect::AnyFs`]: an SFTP-style
//! REPL for poking at an image without paying the open/parse cost on
//! every command. The shell maintains a virtual current directory inside
//! the image and resolves relative paths against it.
//!
//! Commands:
//!
//! ```text
//!   ls [PATH]           list a directory (default: cwd)
//!   pwd                 print the current directory
//!   cd [PATH]           change directory (no arg → /)
//!   cat PATH            print a file's contents to stdout
//!   put HOST [DEST]     copy a host file/dir into the image
//!                       (DEST defaults to the basename of HOST in cwd)
//!   get SRC [DEST]      copy a file/dir out of the image to the host
//!                       (inverse of put; DEST defaults to SRC's basename in
//!                       the host cwd; works in --ro mode)
//!   rm PATH             remove a file or empty directory
//!   mkdir PATH          create an empty directory
//!   info [PATH]         no arg → image summary; with PATH → per-file
//!                       metadata (kind/mode/owner/size/blocks/nlink
//!                       /inode/atime/mtime/ctime/rdev) plus any
//!                       extended attributes (fs-specific properties
//!                       come through here: NTFS DOS attrs, ADS,
//!                       security descriptors; ext / squashfs xattrs;
//!                       HFS+ Finder info; …)
//!   find [PATH] [-name GLOB] [-type f|d|l|b|c|p|s]
//!        [-newer T] [-older T] [-sort mtime|size|name] [-limit N]
//!        [-reverse] [-l]
//!                       recursively list paths (default: cwd), optionally
//!                       filtered by a `*`/`?` name glob, entry type, or
//!                       mtime; `-sort`+`-limit` give e.g. the 200 newest
//!                       files; `-l` adds mtime+size columns. T is a unix
//!                       epoch, a relative age (`7d`, `12h`, `30m`), or an
//!                       ISO date (`2026-01-31`)
//!   grep [-i] [-n] [-r] [-v] [-l] [-c] PATTERN [PATH...]
//!                       search files for the literal PATTERN; text files
//!                       print matching lines, binary files print the
//!                       matching rows as `hexdump -C` output. -v inverts,
//!                       -l lists matching filenames, -c counts matches
//!   help                list these commands
//!   quit | exit         leave
//! ```
//!
//! The shell is just a wrapper around [`fstool::inspect::AnyFs`]; every
//! command dispatches through that, so ext and FAT32 images both work.

use std::io::{BufRead, Write};
use std::path::Path;

use std::sync::atomic::{AtomicBool, Ordering};

use fstool::Result;
use fstool::block::BlockDevice;
use fstool::inspect::{AnyFs, FsKind};
use fstool::path_style::{self, PathStyle};

/// Raised by the SIGINT handler. Long-running commands (`find` / `grep`) poll
/// it and stop cleanly, so Ctrl-C cancels the command without killing the
/// shell. Reset before each command runs.
static INTERRUPT: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn handle_sigint(_sig: libc::c_int) {
    INTERRUPT.store(true, Ordering::SeqCst);
}

/// Install the SIGINT → flag handler exactly once. At the readline prompt
/// rustyline reads Ctrl-C as a keystroke (raw mode, no signal), so this only
/// fires while a command is executing. On non-unix it's a no-op — Ctrl-C keeps
/// its default behaviour there.
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

/// True if a Ctrl-C arrived since the last [`clear_interrupt`].
fn interrupted() -> bool {
    INTERRUPT.load(Ordering::Relaxed)
}

/// Clear the interrupt flag (called before each command runs).
fn clear_interrupt() {
    INTERRUPT.store(false, Ordering::SeqCst);
}

/// Opt-in in-memory metadata cache (`fstool shell --with-cache`). Holds the
/// per-path directory listings and inode attributes so repeated `ls` / `find` /
/// `grep` recursion is served from RAM instead of re-parsing on-disk
/// structures. File *contents* are deliberately not cached. Keys are the
/// shell's canonical (`/`-separated, normalised) path strings.
#[derive(Default)]
struct InodeCache {
    dirs: std::collections::HashMap<String, Vec<fstool::fs::DirEntry>>,
    attrs: std::collections::HashMap<String, fstool::fs::FileAttrs>,
    /// Set once [`Shell::preload`] has walked the whole tree.
    preloaded: bool,
}

/// An interactive shell over an opened image.
pub struct Shell {
    fs: AnyFs,
    /// Current working directory inside the image. Always absolute and
    /// normalised (no `.`/`..`/empty segments), and always in **canonical**
    /// (unix, `/`-separated) form — display translation happens at the edges.
    cwd: String,
    /// True when the shell is in read-only mode (`fstool shell --ro`).
    /// `put` / `rm` / `mkdir` are refused at dispatch time and the
    /// underlying device is opened `O_RDONLY` by the caller.
    read_only: bool,
    /// How the user spells paths (separator + name display). Captured from the
    /// `--path-style` flag.
    style: PathStyle,
    /// The opened filesystem's kind, so path translation knows its native
    /// separator.
    kind: FsKind,
    /// Opt-in metadata cache (`--with-cache`). `None` = caching off (default).
    cache: Option<InodeCache>,
}

impl Shell {
    /// A new shell rooted at `/` over `fs`. The shell is mutating —
    /// `put` / `rm` / `mkdir` go through to the FS writer.
    pub fn new(fs: AnyFs, style: PathStyle) -> Self {
        let kind = fs.kind();
        Self {
            fs,
            cwd: "/".into(),
            read_only: false,
            style,
            kind,
            cache: None,
        }
    }

    /// A read-only shell over `fs`. `put` / `rm` / `mkdir` refuse
    /// with a clear error; only `ls` / `cat` / `cd` / `pwd` / `info`
    /// / `help` work. Intended for `fstool shell --ro` where the
    /// caller has opened the BlockDevice read-only (so even a
    /// missed gate fails at the syscall).
    pub fn new_read_only(fs: AnyFs, style: PathStyle) -> Self {
        let kind = fs.kind();
        Self {
            fs,
            cwd: "/".into(),
            read_only: true,
            style,
            kind,
            cache: None,
        }
    }

    /// Turn on the opt-in in-memory metadata cache (`--with-cache`). Reads
    /// (`list` / `getattr`) are served from / filled into the cache; call
    /// [`Shell::preload`] to populate it eagerly before the first prompt.
    pub fn enable_cache(&mut self) {
        if self.cache.is_none() {
            self.cache = Some(InodeCache::default());
        }
    }

    /// Directory listing for `path`, served from the cache when enabled and
    /// populated on a miss. The single choke point for `list` reads so the
    /// cache stays coherent.
    fn list(&mut self, dev: &mut dyn BlockDevice, path: &str) -> Result<Vec<fstool::fs::DirEntry>> {
        if let Some(c) = &self.cache
            && let Some(v) = c.dirs.get(path)
        {
            return Ok(v.clone());
        }
        let v = self.fs.list(dev, path)?;
        if let Some(c) = &mut self.cache {
            c.dirs.insert(path.to_string(), v.clone());
        }
        Ok(v)
    }

    /// Attributes for `path`, served from the cache when enabled and populated
    /// on a miss. The single choke point for `getattr` reads.
    fn getattr(&mut self, dev: &mut dyn BlockDevice, path: &str) -> Result<fstool::fs::FileAttrs> {
        if let Some(c) = &self.cache
            && let Some(a) = c.attrs.get(path)
        {
            return Ok(*a);
        }
        let a = self.fs.getattr(dev, Path::new(path))?;
        if let Some(c) = &mut self.cache {
            c.attrs.insert(path.to_string(), a);
        }
        Ok(a)
    }

    /// Drop every cached entry (after a mutation). The next read lazily
    /// refills. A no-op when caching is off.
    fn invalidate_cache(&mut self) {
        if let Some(c) = &mut self.cache {
            c.dirs.clear();
            c.attrs.clear();
            c.preloaded = false;
        }
    }

    /// Eagerly walk the whole tree to fill the cache, so the first `find` /
    /// `ls` is instant. No-op unless caching is on and not already preloaded.
    /// Per-directory errors are skipped (a partial cache is still correct — the
    /// read helpers lazily fill any gaps), and Ctrl-C aborts a long preload.
    pub fn preload(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        match &self.cache {
            Some(c) if !c.preloaded => {}
            _ => return Ok(()),
        }
        install_interrupt_handler();
        clear_interrupt();
        let start = std::time::Instant::now();
        let (mut dirs, mut entries) = (0u64, 0u64);
        let _ = self.getattr(dev, "/");
        let mut stack = vec!["/".to_string()];
        while let Some(dir) = stack.pop() {
            if interrupted() {
                break;
            }
            let listing = match self.list(dev, &dir) {
                Ok(l) => l,
                Err(_) => continue, // unreadable dir: skip, lazy-fill later
            };
            dirs += 1;
            for e in listing {
                if e.name == "." || e.name == ".." {
                    continue;
                }
                let child = join(&dir, &e.name);
                let _ = self.getattr(dev, &child);
                entries += 1;
                if matches!(e.kind, fstool::fs::EntryKind::Dir) {
                    stack.push(child);
                }
            }
        }
        let aborted = interrupted();
        if let Some(c) = &mut self.cache {
            c.preloaded = !aborted;
        }
        eprintln!(
            "cache: preloaded {dirs} dirs / {entries} entries in {} ms{}",
            start.elapsed().as_millis(),
            if aborted {
                " (interrupted; partial)"
            } else {
                ""
            }
        );
        Ok(())
    }

    /// Read commands from `input` line by line and execute each one against
    /// `dev`, writing prompts, results, and errors to `output`. Returns
    /// when the input stream reaches EOF or the user runs `quit` / `exit`.
    /// Errors from individual commands are reported and the loop continues —
    /// only I/O errors on the input or output streams propagate.
    pub fn run(
        &mut self,
        dev: &mut dyn BlockDevice,
        mut input: impl BufRead,
        mut output: impl Write,
    ) -> Result<()> {
        install_interrupt_handler();
        loop {
            write!(
                output,
                "fstool:{}> ",
                path_style::display_path(&self.cwd, self.kind, self.style)
            )?;
            output.flush()?;
            let mut line = String::new();
            let n = input.read_line(&mut line)?;
            if n == 0 {
                writeln!(output)?; // newline so the next shell prompt isn't on our line
                break;
            }
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            clear_interrupt();
            match self.dispatch(dev, line, &mut output) {
                Ok(true) => break,
                Ok(false) => {}
                Err(e) => writeln!(output, "error: {e}")?,
            }
        }
        Ok(())
    }

    /// Interactive REPL with line editing and command history (↑/↓ to recall
    /// previous commands, Ctrl-A/E, Ctrl-R search, …) via `rustyline`. Used
    /// when stdin is a TTY; piped input still flows through [`Shell::run`],
    /// which keeps the deterministic, testable line-buffered path.
    ///
    /// History persists to `~/.fstool_history` between sessions. `Ctrl-C`
    /// abandons the current line and re-prompts; `Ctrl-D` at an empty prompt
    /// exits, matching a typical Unix shell.
    #[cfg(feature = "readline")]
    pub fn run_interactive(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        use rustyline::error::ReadlineError;

        install_interrupt_handler();

        let mut rl = rustyline::DefaultEditor::new()
            .map_err(|e| fstool::Error::Io(std::io::Error::other(e.to_string())))?;
        let history = history_path();
        if let Some(path) = history.as_ref() {
            // A missing history file on first run is fine.
            let _ = rl.load_history(path);
        }

        let mut output = std::io::stdout().lock();
        loop {
            let prompt = format!(
                "fstool:{}> ",
                path_style::display_path(&self.cwd, self.kind, self.style)
            );
            match rl.readline(&prompt) {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let _ = rl.add_history_entry(trimmed);
                    clear_interrupt();
                    match self.dispatch(dev, trimmed, &mut output) {
                        Ok(true) => break,
                        Ok(false) => {}
                        Err(e) => writeln!(output, "error: {e}")?,
                    }
                }
                // Ctrl-C: drop the half-typed line and re-prompt.
                Err(ReadlineError::Interrupted) => continue,
                // Ctrl-D at the prompt: exit the shell.
                Err(ReadlineError::Eof) => break,
                Err(e) => return Err(fstool::Error::Io(std::io::Error::other(e.to_string()))),
            }
        }

        if let Some(path) = history.as_ref() {
            let _ = rl.save_history(path);
        }
        Ok(())
    }

    /// Dispatch one command line. Returns `Ok(true)` if the shell should
    /// exit (`quit` / `exit`), `Ok(false)` to continue, or an `Err` for
    /// the loop to print and recover from.
    fn dispatch(
        &mut self,
        dev: &mut dyn BlockDevice,
        line: &str,
        output: &mut impl Write,
    ) -> Result<bool> {
        let (cmd, rest) = split_cmd(line);
        match cmd {
            "quit" | "exit" | ":q" => Ok(true),
            "help" | "?" => {
                self.cmd_help(output)?;
                Ok(false)
            }
            "pwd" => {
                writeln!(
                    output,
                    "{}",
                    path_style::display_path(&self.cwd, self.kind, self.style)
                )?;
                Ok(false)
            }
            "ls" => {
                self.cmd_ls(dev, rest, output)?;
                Ok(false)
            }
            "cd" => {
                self.cmd_cd(dev, rest)?;
                Ok(false)
            }
            "cat" => {
                self.cmd_cat(dev, rest, output)?;
                Ok(false)
            }
            "put" => {
                self.require_writable("put")?;
                self.cmd_put(dev, rest, output)?;
                Ok(false)
            }
            "get" => {
                self.cmd_get(dev, rest, output)?;
                Ok(false)
            }
            "save" => {
                self.cmd_save(dev, rest, output)?;
                Ok(false)
            }
            "rm" => {
                self.require_writable("rm")?;
                self.cmd_rm(dev, rest, output)?;
                Ok(false)
            }
            "mkdir" => {
                self.require_writable("mkdir")?;
                self.cmd_mkdir(dev, rest, output)?;
                Ok(false)
            }
            "info" => {
                self.cmd_info(dev, rest, output)?;
                Ok(false)
            }
            "df" => {
                self.cmd_df(dev, output)?;
                Ok(false)
            }
            "find" => {
                self.cmd_find(dev, rest, output)?;
                Ok(false)
            }
            "grep" => {
                self.cmd_grep(dev, rest, output)?;
                Ok(false)
            }
            "" => Ok(false),
            other => Err(fstool::Error::InvalidArgument(format!(
                "unknown command {other:?} (try `help`)"
            ))),
        }
    }

    /// Refuse a mutating command when the shell is in `--ro` mode.
    /// The underlying BlockDevice is also opened `O_RDONLY` so a
    /// missed gate would still fail at the syscall, but this gives
    /// the user a clean error rather than `PermissionDenied`.
    fn require_writable(&self, cmd: &str) -> Result<()> {
        if self.read_only {
            return Err(fstool::Error::InvalidArgument(format!(
                "{cmd}: shell is read-only (started with --ro); restart \
                 without --ro to mutate the image",
            )));
        }
        Ok(())
    }

    fn cmd_help(&self, output: &mut impl Write) -> Result<()> {
        let ro_note = if self.read_only {
            "\n(shell is read-only: put / rm / mkdir refuse — restart without --ro to mutate)\n"
        } else {
            ""
        };
        let cache_note = if self.cache.is_some() {
            "(metadata cache active: --with-cache — ls / find / grep metadata served from RAM)\n"
        } else {
            ""
        };
        let body = format!(
            "ls [PATH]           list a directory (default: cwd)
pwd                 print the current directory
cd [PATH]           change directory (no arg → /)
cat PATH            print a file's contents to stdout
put HOST [DEST]     copy a host file or directory into the image
get SRC [DEST]      copy a file or directory out of the image to the host
                    (inverse of put; DEST defaults to SRC's basename in the
                    host cwd, or names a target/existing dir; works read-only)
rm PATH             remove a file or empty directory
mkdir PATH          create an empty directory
info [PATH]         no arg → image summary; with PATH → file metadata
                    (kind/mode/owner/size/blocks/nlink/inode/atime/mtime
                    /ctime/rdev) plus any extended attributes
df                  filesystem capacity (statfs): block size, total / used /
                    free space and inode counts
find [PATH] [-name GLOB] [-type f|d|l|b|c|p|s] [-newer T] [-older T]
     [-sort mtime|size|name] [-limit N] [-reverse] [-l]
                    recursively list paths under PATH (default: cwd), filtered
                    by name glob (* ?), type, and/or mtime. -sort + -limit list
                    e.g. the 200 newest files; -l adds mtime+size columns.
                    T = unix epoch, relative age (7d/12h/30m), or ISO date.
grep [-i] [-n] [-r] [-v] [-l] [-c] PATTERN [PATH...]
                    search files for the literal PATTERN (default PATH: cwd
                    with -r). -i case-insensitive, -n line numbers, -r recurse,
                    -v invert, -l list matching filenames, -c count matches.
                    Binary files print their matches as `hexdump -C` rows
                    (Ctrl-C cancels a running find/grep without leaving the shell)
save OUT[.tar[.gz|.zst|.xz]]
                    snapshot the whole tree to a (optionally compressed) tar
                    on the host — symlinks, devices and xattrs preserved. Handy
                    for a `--new-ramfs` session; `fstool repack OUT image -t …`
                    then builds an exactly-sized real filesystem from it.
help | ?            print this help
quit | exit         leave{ro_note}\n{cache_note}"
        );
        output.write_all(body.as_bytes())?;
        Ok(())
    }

    fn cmd_ls(
        &mut self,
        dev: &mut dyn BlockDevice,
        arg: &str,
        output: &mut impl Write,
    ) -> Result<()> {
        let target = if arg.is_empty() {
            self.cwd.clone()
        } else {
            self.resolve(arg)
        };
        let entries = self.list(dev, &target)?;
        for e in &entries {
            let suffix = match e.kind {
                fstool::fs::EntryKind::Dir => "/",
                fstool::fs::EntryKind::Symlink => "@",
                _ => "",
            };
            writeln!(
                output,
                "{}{}",
                crate::safety::sanitize_name(&path_style::display_name(
                    &e.name, self.kind, self.style
                )),
                suffix
            )?;
        }
        Ok(())
    }

    fn cmd_cd(&mut self, dev: &mut dyn BlockDevice, arg: &str) -> Result<()> {
        let target = if arg.is_empty() {
            "/".to_string()
        } else {
            self.resolve(arg)
        };
        // Verify it's actually a directory by listing it. Cheap, and gives
        // a useful error if the path is wrong.
        self.list(dev, &target)?;
        self.cwd = target;
        Ok(())
    }

    fn cmd_cat(
        &mut self,
        dev: &mut dyn BlockDevice,
        arg: &str,
        output: &mut impl Write,
    ) -> Result<()> {
        if arg.is_empty() {
            return Err(fstool::Error::InvalidArgument(
                "cat: PATH is required".into(),
            ));
        }
        let path = self.resolve(arg);
        self.fs.copy_file_to(dev, &path, output)?;
        Ok(())
    }

    fn cmd_put(
        &mut self,
        dev: &mut dyn BlockDevice,
        arg: &str,
        output: &mut impl Write,
    ) -> Result<()> {
        let mut parts = arg.splitn(2, char::is_whitespace);
        let host_str = parts.next().unwrap_or("").trim();
        let dest_arg = parts.next().unwrap_or("").trim();
        if host_str.is_empty() {
            return Err(fstool::Error::InvalidArgument(
                "put: HOST is required".into(),
            ));
        }
        let host = Path::new(host_str);
        let meta = std::fs::symlink_metadata(host)?;
        let dest = if dest_arg.is_empty() {
            let leaf = host.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
                fstool::Error::InvalidArgument(
                    "put: HOST has no usable leaf name; specify DEST explicitly".into(),
                )
            })?;
            join(&self.cwd, leaf)
        } else {
            self.resolve(dest_arg)
        };
        if meta.is_dir() {
            self.fs.add_dir_tree(dev, &dest, host)?;
        } else if meta.is_file() {
            self.fs.add_file(dev, &dest, host)?;
        } else {
            return Err(fstool::Error::InvalidArgument(format!(
                "put: {} is neither a regular file nor a directory",
                host.display()
            )));
        }
        self.fs.flush(dev)?;
        dev.sync()?;
        self.invalidate_cache();
        writeln!(output, "put {} → {dest}", host.display())?;
        Ok(())
    }

    /// `get SRC [DEST]` — copy a file (or directory tree) **out** of the image
    /// to the host. The inverse of `put`; read-only, so it works in `--ro` mode
    /// too. `SRC` is a path inside the image; `DEST` is a host path. When `DEST`
    /// is omitted the file lands under `SRC`'s basename in the host's current
    /// directory; when `DEST` names an existing host directory the basename is
    /// appended. A directory `SRC` is copied recursively (regular files and,
    /// on unix, symlinks; other special files are skipped with a note).
    fn cmd_get(
        &mut self,
        dev: &mut dyn BlockDevice,
        arg: &str,
        output: &mut impl Write,
    ) -> Result<()> {
        let mut parts = arg.splitn(2, char::is_whitespace);
        let src_arg = parts.next().unwrap_or("").trim();
        let dest_arg = parts.next().unwrap_or("").trim();
        if src_arg.is_empty() {
            return Err(fstool::Error::InvalidArgument(
                "get: SRC (a path inside the image) is required".into(),
            ));
        }
        let src = self.resolve(src_arg);
        let attrs = self.getattr(dev, &src)?;
        let leaf = src
            .rsplit('/')
            .find(|s| !s.is_empty())
            .unwrap_or("image_root");

        // Resolve the host destination: an existing directory receives the
        // basename; otherwise DEST is the literal target path; empty DEST
        // means the basename in the host's current directory.
        let dest: std::path::PathBuf = if dest_arg.is_empty() {
            std::path::PathBuf::from(leaf)
        } else {
            let d = std::path::PathBuf::from(dest_arg);
            if d.is_dir() { d.join(leaf) } else { d }
        };

        let src_disp = path_style::display_path(&src, self.kind, self.style);
        match attrs.kind {
            fstool::fs::EntryKind::Regular => {
                self.get_file(dev, &src, &dest)?;
                writeln!(output, "get {src_disp} → {}", dest.display())?;
            }
            fstool::fs::EntryKind::Dir => {
                let n = self.get_dir(dev, &src, &dest, output)?;
                writeln!(output, "get {src_disp} → {} ({n} files)", dest.display())?;
            }
            fstool::fs::EntryKind::Symlink => {
                let target = self.fs.read_symlink(dev, &src)?;
                write_host_symlink(&target, &dest)?;
                writeln!(output, "get {src_disp} → {} (symlink)", dest.display())?;
            }
            other => {
                return Err(fstool::Error::InvalidArgument(format!(
                    "get: {src_disp} is a {other:?}; only regular files, directories, \
                     and symlinks can be extracted"
                )));
            }
        }
        Ok(())
    }

    /// `save OUT` — snapshot the whole filesystem to a tar on the host
    /// (compression inferred from the extension). Walks the live tree through
    /// the same sink the `repack` command uses, so symlinks, devices and
    /// xattrs are preserved. Works in `--ro` mode too (it only reads the
    /// image and writes to the host). Compose with `fstool repack OUT image
    /// -t <fs>` to materialise an exactly-sized real filesystem.
    fn cmd_save(
        &mut self,
        dev: &mut dyn BlockDevice,
        arg: &str,
        output: &mut impl Write,
    ) -> Result<()> {
        use fstool::repack::RepackSink;
        let out = arg.trim();
        if out.is_empty() {
            return Err(fstool::Error::InvalidArgument(
                "save: OUT (a host path, e.g. snap.tar / snap.tar.zst) is required".into(),
            ));
        }
        let path = std::path::Path::new(out);
        let codec = crate::tar_output_codec(path);
        let file = std::fs::File::create(path)?;
        let buffered: Box<dyn Write> = Box::new(std::io::BufWriter::with_capacity(64 * 1024, file));
        let inner = match codec {
            Some(algo) => fstool::compression::make_writer(algo, buffered)?,
            None => buffered,
        };
        let mut sink = fstool::repack::TarStreamSink::new(inner);
        fstool::repack::walk_anyfs(&mut self.fs, dev, &mut sink)?;
        sink.finish()?;
        let written = sink.bytes_written();
        let label = match codec {
            Some(algo) => format!("tar.{}", algo.name()),
            None => "tar".to_string(),
        };
        writeln!(output, "saved → {out} ({label}, {written} bytes plain)")?;
        Ok(())
    }

    /// Copy one regular file out of the image to host path `dest`, creating
    /// parent directories as needed.
    fn get_file(&mut self, dev: &mut dyn BlockDevice, src: &str, dest: &Path) -> Result<()> {
        if let Some(parent) = dest.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::File::create(dest)?;
        self.fs.copy_file_to(dev, src, &mut f)?;
        Ok(())
    }

    /// Recursively copy directory `src` (an image path) to host directory
    /// `dest`. Returns the number of regular files written. Cancellable with
    /// Ctrl-C (leaves whatever was copied so far in place).
    fn get_dir(
        &mut self,
        dev: &mut dyn BlockDevice,
        src: &str,
        dest: &Path,
        output: &mut impl Write,
    ) -> Result<u64> {
        std::fs::create_dir_all(dest)?;
        let mut files = 0u64;
        let mut stack = vec![(src.to_string(), dest.to_path_buf())];
        'walk: while let Some((idir, hdir)) = stack.pop() {
            if interrupted() {
                break;
            }
            for e in self.list(dev, &idir)? {
                if interrupted() {
                    break 'walk;
                }
                if e.name == "." || e.name == ".." {
                    continue;
                }
                // The entry name is attacker-controlled: a name containing
                // `..`, a separator, or an absolute path would escape `hdir`
                // (Path::join with an absolute path replaces the base) and let
                // a malicious image write anywhere on the host. Skip anything
                // that isn't a single ordinary path component. (CLI-1 / CLI-3)
                if !crate::safety::safe_component(&e.name) {
                    eprintln!(
                        "get: skipping entry with unsafe name {:?} under {}",
                        crate::safety::sanitize_name(&e.name),
                        idir
                    );
                    continue;
                }
                let ichild = join(&idir, &e.name);
                let hchild = hdir.join(&e.name);
                match e.kind {
                    fstool::fs::EntryKind::Dir => {
                        std::fs::create_dir_all(&hchild)?;
                        stack.push((ichild, hchild));
                    }
                    fstool::fs::EntryKind::Regular => {
                        let mut f = std::fs::File::create(&hchild)?;
                        self.fs.copy_file_to(dev, &ichild, &mut f)?;
                        files += 1;
                    }
                    fstool::fs::EntryKind::Symlink => {
                        let target = self.fs.read_symlink(dev, &ichild)?;
                        write_host_symlink(&target, &hchild)?;
                    }
                    other => {
                        writeln!(output, "get: skipping {} ({other:?})", hchild.display())?;
                    }
                }
            }
        }
        if interrupted() {
            writeln!(output, "^C")?;
        }
        Ok(files)
    }

    fn cmd_rm(
        &mut self,
        dev: &mut dyn BlockDevice,
        arg: &str,
        output: &mut impl Write,
    ) -> Result<()> {
        if arg.is_empty() {
            return Err(fstool::Error::InvalidArgument(
                "rm: PATH is required".into(),
            ));
        }
        let path = self.resolve(arg);
        if path == "/" {
            return Err(fstool::Error::InvalidArgument(
                "rm: refusing to remove /".into(),
            ));
        }
        self.fs.remove(dev, &path)?;
        self.fs.flush(dev)?;
        dev.sync()?;
        self.invalidate_cache();
        writeln!(output, "removed {path}")?;
        Ok(())
    }

    fn cmd_mkdir(
        &mut self,
        dev: &mut dyn BlockDevice,
        arg: &str,
        output: &mut impl Write,
    ) -> Result<()> {
        if arg.is_empty() {
            return Err(fstool::Error::InvalidArgument(
                "mkdir: PATH is required".into(),
            ));
        }
        let path = self.resolve(arg);
        self.fs.mkdir(dev, &path)?;
        self.fs.flush(dev)?;
        dev.sync()?;
        self.invalidate_cache();
        writeln!(output, "mkdir {path}")?;
        Ok(())
    }

    fn cmd_info(
        &mut self,
        dev: &mut dyn BlockDevice,
        arg: &str,
        output: &mut impl Write,
    ) -> Result<()> {
        // No path → image-level summary, unchanged behaviour.
        if arg.is_empty() {
            writeln!(output, "fs kind: {}", self.fs.kind_string())?;
            return Ok(());
        }

        // With a path → per-file metadata. `getattr` returns the
        // POSIX-ish fields every backend can answer; `list_xattrs`
        // surfaces fs-specific properties (NTFS DOS attrs, ADS, security
        // descriptors; ext / squashfs xattrs; HFS+ Finder info; …).
        let path = self.resolve(arg);
        let attrs = self.getattr(dev, &path)?;

        writeln!(output, "path:   {}", crate::safety::sanitize_name(&path))?;
        writeln!(output, "kind:   {}", fmt_kind(attrs.kind))?;
        writeln!(
            output,
            "mode:   {:04o}  ({})",
            attrs.mode & 0o7777,
            fmt_mode(attrs.kind, attrs.mode)
        )?;
        writeln!(output, "owner:  {}:{}", attrs.uid, attrs.gid)?;
        writeln!(output, "size:   {} bytes", attrs.size)?;
        writeln!(output, "blocks: {}  (512-byte units)", attrs.blocks)?;
        writeln!(output, "nlink:  {}", attrs.nlink)?;
        writeln!(output, "inode:  {}", attrs.inode)?;
        writeln!(
            output,
            "atime:  {}  ({})",
            attrs.atime,
            fmt_unix_utc(attrs.atime)
        )?;
        writeln!(
            output,
            "mtime:  {}  ({})",
            attrs.mtime,
            fmt_unix_utc(attrs.mtime)
        )?;
        writeln!(
            output,
            "ctime:  {}  ({})",
            attrs.ctime,
            fmt_unix_utc(attrs.ctime)
        )?;
        match attrs.kind {
            fstool::fs::EntryKind::Char | fstool::fs::EntryKind::Block => {
                let (maj, min) = fstool::fs::ext::inode::decode_devnum(attrs.rdev);
                writeln!(
                    output,
                    "rdev:   {:#x}  (major {maj}, minor {min})",
                    attrs.rdev
                )?;
            }
            _ => writeln!(output, "rdev:   -")?,
        }

        // Symlinks: also surface the target. Backends that don't carry
        // symlinks (FAT/exFAT) error here; we just skip on error so
        // info on a non-symlink still works.
        if matches!(attrs.kind, fstool::fs::EntryKind::Symlink)
            && let Ok(tgt) = self.fs.read_symlink(dev, &path)
        {
            writeln!(output, "target: {}", crate::safety::sanitize_name(&tgt))?;
        }

        // Extended attributes — fs-specific metadata in a generic shape.
        // Empty xattr lists are common (most ext images, most files),
        // so omit the section entirely when none.
        let xattrs = self.fs.list_xattrs(dev, Path::new(&path))?;
        if !xattrs.is_empty() {
            writeln!(output)?;
            writeln!(output, "xattrs ({}):", xattrs.len())?;
            for xa in &xattrs {
                writeln!(
                    output,
                    "  {:<28} = {}",
                    crate::safety::sanitize_name(&xa.name),
                    fmt_xattr_value(&xa.value)
                )?;
            }
        }
        Ok(())
    }

    /// `df` — print the filesystem's capacity stats (the same `statfs` view
    /// the FUSE adapter answers `df` with). Backends without a real superblock
    /// report zero counts, shown verbatim.
    fn cmd_df(&mut self, dev: &mut dyn BlockDevice, output: &mut impl Write) -> Result<()> {
        let s = self.fs.statfs(dev)?;
        let bs = u64::from(s.block_size);
        let used = s.blocks.saturating_sub(s.blocks_free);
        writeln!(output, "filesystem:  {}", self.fs.kind_string())?;
        writeln!(output, "block size:  {} bytes", s.block_size)?;
        writeln!(
            output,
            "size:        {} ({} blocks)",
            crate::human_size(s.blocks * bs),
            s.blocks
        )?;
        writeln!(
            output,
            "used:        {} ({} blocks)",
            crate::human_size(used * bs),
            used
        )?;
        writeln!(
            output,
            "free:        {} ({} blocks, {} avail)",
            crate::human_size(s.blocks_free * bs),
            s.blocks_free,
            s.blocks_avail
        )?;
        writeln!(
            output,
            "inodes:      {} total, {} free",
            s.inodes, s.inodes_free
        )?;
        if s.blocks == 0 && s.inodes == 0 {
            writeln!(output, "(this backend does not report statfs counts)")?;
        }
        Ok(())
    }

    /// `find [PATH] [-name GLOB] [-type f|d|l|b|c|p|s] [-newer T] [-older T]
    /// [-sort mtime|size|name] [-limit N] [-reverse] [-l]` — recursively print
    /// every path under PATH (default cwd), filtered by a basename glob, an
    /// entry type, and/or mtime (`T` = unix epoch, relative age like `7d`, or
    /// ISO date). `-sort` with `-limit` yields, e.g., the N most recently
    /// modified files; `-l` prefixes each line with its mtime and size. Without
    /// `-sort`, results stream in walk order; with it, all hits are collected,
    /// sorted, then truncated. Paths print in the active display style.
    #[allow(clippy::too_many_lines)]
    fn cmd_find(
        &mut self,
        dev: &mut dyn BlockDevice,
        arg: &str,
        output: &mut impl Write,
    ) -> Result<()> {
        let mut start: Option<String> = None;
        let mut name: Option<String> = None;
        let mut type_filter: Option<char> = None;
        let mut newer: Option<u64> = None;
        let mut older: Option<u64> = None;
        let mut sort: Option<SortKey> = None;
        let mut limit: Option<usize> = None;
        let mut reverse = false;
        let mut long = false;
        let mut toks = arg.split_whitespace();
        let next_val = |toks: &mut std::str::SplitWhitespace, flag: &str| -> Result<String> {
            toks.next().map(str::to_string).ok_or_else(|| {
                fstool::Error::InvalidArgument(format!("find: {flag} needs a value"))
            })
        };
        while let Some(tok) = toks.next() {
            match tok {
                "-name" => name = Some(next_val(&mut toks, "-name")?),
                "-type" => {
                    let t = next_val(&mut toks, "-type")?;
                    let c = t.chars().next().filter(|_| t.len() == 1);
                    match c {
                        Some(c @ ('f' | 'd' | 'l' | 'b' | 'c' | 'p' | 's')) => {
                            type_filter = Some(c)
                        }
                        _ => {
                            return Err(fstool::Error::InvalidArgument(format!(
                                "find: -type {t:?} (use one of f d l b c p s)"
                            )));
                        }
                    }
                }
                "-newer" => newer = Some(parse_timespec(&next_val(&mut toks, "-newer")?)?),
                "-older" => older = Some(parse_timespec(&next_val(&mut toks, "-older")?)?),
                "-sort" => {
                    let k = next_val(&mut toks, "-sort")?;
                    sort = Some(match k.as_str() {
                        "mtime" | "time" => SortKey::Mtime,
                        "size" => SortKey::Size,
                        "name" => SortKey::Name,
                        other => {
                            return Err(fstool::Error::InvalidArgument(format!(
                                "find: -sort {other:?} (use mtime, size, or name)"
                            )));
                        }
                    });
                }
                "-limit" | "-n" => {
                    let v = next_val(&mut toks, tok)?;
                    limit = Some(v.parse().map_err(|_| {
                        fstool::Error::InvalidArgument(format!("find: bad -limit {v:?}"))
                    })?);
                }
                "-reverse" => reverse = true,
                "-l" => long = true,
                _ if tok.starts_with('-') => {
                    return Err(fstool::Error::InvalidArgument(format!(
                        "find: unknown option {tok:?}"
                    )));
                }
                _ if start.is_none() => start = Some(self.resolve(tok)),
                _ => {
                    return Err(fstool::Error::InvalidArgument(
                        "find: only one starting PATH is supported".into(),
                    ));
                }
            }
        }
        let start = start.unwrap_or_else(|| self.cwd.clone());
        // mtime is needed for time filters, mtime sorting, or long output.
        let need_mtime =
            newer.is_some() || older.is_some() || matches!(sort, Some(SortKey::Mtime)) || long;

        let passes = |kind: fstool::fs::EntryKind, ename: &str, mtime: u32| -> bool {
            let type_ok = type_filter
                .map(|t| kind_type_letter(kind) == t)
                .unwrap_or(true);
            let name_ok = name
                .as_deref()
                .map(|g| glob_match(g.as_bytes(), ename.as_bytes()))
                .unwrap_or(true);
            let time_ok = newer.map(|t| u64::from(mtime) > t).unwrap_or(true)
                && older.map(|t| u64::from(mtime) < t).unwrap_or(true);
            type_ok && name_ok && time_ok
        };

        let mut hits: Vec<Hit> = Vec::new();
        let streaming = sort.is_none();
        let style = (self.kind, self.style);
        let emit = |h: Hit, output: &mut dyn Write| -> Result<()> {
            if long {
                writeln!(
                    output,
                    "{}  {:>12}  {}",
                    fmt_unix_utc(h.mtime),
                    h.size,
                    crate::safety::sanitize_name(&path_style::display_path(
                        &h.path, style.0, style.1
                    ))
                )?;
            } else {
                writeln!(
                    output,
                    "{}",
                    crate::safety::sanitize_name(&path_style::display_path(
                        &h.path, style.0, style.1
                    ))
                )?;
            }
            Ok(())
        };
        let mut emitted = 0usize;

        // The start path itself.
        let sa = self.getattr(dev, &start)?;
        let start_name = start.rsplit('/').next().unwrap_or("");
        if passes(sa.kind, start_name, sa.mtime) {
            let h = Hit {
                path: start.clone(),
                size: sa.size,
                mtime: sa.mtime,
            };
            if streaming {
                emit(h, output)?;
                emitted += 1;
            } else {
                hits.push(h);
            }
        }

        if matches!(sa.kind, fstool::fs::EntryKind::Dir) {
            let mut stack = vec![start];
            'walk: while let Some(dir) = stack.pop() {
                if interrupted() {
                    break;
                }
                for e in self.list(dev, &dir)? {
                    if interrupted() {
                        break 'walk;
                    }
                    if e.name == "." || e.name == ".." {
                        continue;
                    }
                    let child = join(&dir, &e.name);
                    if matches!(e.kind, fstool::fs::EntryKind::Dir) {
                        stack.push(child.clone());
                    }
                    // Cheap filters first; only fetch mtime when actually needed.
                    let cheap_ok = type_filter
                        .map(|t| kind_type_letter(e.kind) == t)
                        .unwrap_or(true)
                        && name
                            .as_deref()
                            .map(|g| glob_match(g.as_bytes(), e.name.as_bytes()))
                            .unwrap_or(true);
                    if !cheap_ok {
                        continue;
                    }
                    let mtime = if need_mtime {
                        self.getattr(dev, &child)?.mtime
                    } else {
                        0
                    };
                    if !passes(e.kind, &e.name, mtime) {
                        continue;
                    }
                    let h = Hit {
                        path: child,
                        size: e.size,
                        mtime,
                    };
                    if streaming {
                        emit(h, output)?;
                        emitted += 1;
                        if limit.is_some_and(|n| emitted >= n) {
                            break 'walk;
                        }
                    } else {
                        hits.push(h);
                    }
                }
            }
        }

        if !streaming {
            match sort.unwrap() {
                SortKey::Mtime => hits.sort_by_key(|h| std::cmp::Reverse(h.mtime)), // newest first
                SortKey::Size => hits.sort_by_key(|h| std::cmp::Reverse(h.size)),   // largest first
                SortKey::Name => hits.sort_by(|a, b| a.path.cmp(&b.path)),          // A→Z
            }
            if reverse {
                hits.reverse();
            }
            if let Some(n) = limit {
                hits.truncate(n);
            }
            for h in hits {
                emit(h, output)?;
            }
        }
        if interrupted() {
            writeln!(output, "^C")?;
        }
        Ok(())
    }

    /// `grep [-i] [-n] [-r] PATTERN [PATH...]` — search files for the literal
    /// `PATTERN`. Text files print matching lines; binary files (NUL byte or
    /// non-UTF-8) print the rows containing matches as `hexdump -C` output.
    fn cmd_grep(
        &mut self,
        dev: &mut dyn BlockDevice,
        arg: &str,
        output: &mut impl Write,
    ) -> Result<()> {
        let (mut ci, mut numbers, mut recurse) = (false, false, false);
        let (mut invert, mut list, mut count) = (false, false, false);
        let mut pattern: Option<String> = None;
        let mut paths: Vec<String> = Vec::new();
        for tok in arg.split_whitespace() {
            if pattern.is_none() && tok.starts_with('-') && tok.len() > 1 {
                for f in tok[1..].chars() {
                    match f {
                        'i' => ci = true,
                        'n' => numbers = true,
                        'r' | 'R' => recurse = true,
                        'v' => invert = true,
                        'l' => list = true,
                        'c' => count = true,
                        other => {
                            return Err(fstool::Error::InvalidArgument(format!(
                                "grep: unknown flag -{other}"
                            )));
                        }
                    }
                }
            } else if pattern.is_none() {
                pattern = Some(tok.to_string());
            } else {
                paths.push(self.resolve(tok));
            }
        }
        let pattern = pattern
            .ok_or_else(|| fstool::Error::InvalidArgument("grep: PATTERN is required".into()))?;
        let needle = pattern.as_bytes();
        if paths.is_empty() {
            paths.push(self.cwd.clone());
        }

        // Expand the targets into a flat list of regular-file paths.
        let mut files: Vec<String> = Vec::new();
        for p in paths {
            match self.getattr(dev, &p)?.kind {
                fstool::fs::EntryKind::Dir => {
                    if !recurse {
                        writeln!(
                            output,
                            "grep: {}: is a directory (use -r)",
                            crate::safety::sanitize_name(&p)
                        )?;
                        continue;
                    }
                    let mut stack = vec![p];
                    while let Some(dir) = stack.pop() {
                        if interrupted() {
                            break;
                        }
                        for e in self.list(dev, &dir)? {
                            if e.name == "." || e.name == ".." {
                                continue;
                            }
                            let child = join(&dir, &e.name);
                            match e.kind {
                                fstool::fs::EntryKind::Dir => stack.push(child),
                                fstool::fs::EntryKind::Regular => files.push(child),
                                _ => {}
                            }
                        }
                    }
                }
                fstool::fs::EntryKind::Regular => files.push(p),
                _ => writeln!(
                    output,
                    "grep: {}: not a regular file",
                    crate::safety::sanitize_name(&p)
                )?,
            }
        }
        let opts = GrepOpts {
            ci,
            numbers,
            invert,
            list,
            count,
            show_name: files.len() > 1 || recurse,
        };

        const CAP: u64 = 256 * 1024 * 1024;
        for path in files {
            if interrupted() {
                break;
            }
            let size = self.getattr(dev, &path)?.size;
            if size > CAP {
                writeln!(
                    output,
                    "grep: {}: file too large ({size} bytes), skipped",
                    crate::safety::sanitize_name(&path)
                )?;
                continue;
            }
            let mut data = Vec::with_capacity(size as usize);
            self.fs.copy_file_to(dev, &path, &mut data)?;
            if is_binary(&data) {
                grep_binary(&path, &data, needle, opts, output)?;
            } else {
                grep_text(&path, &data, needle, opts, output)?;
            }
        }
        if interrupted() {
            writeln!(output, "^C")?;
        }
        Ok(())
    }

    /// Resolve a user-typed `path` against [`Self::cwd`]. The input is first
    /// translated from the active [`PathStyle`] into canonical (`/`-separated)
    /// form; absolute canonical paths normalise as themselves, relative ones
    /// are joined onto cwd. Both then go through [`normalize_path`] to collapse
    /// `.`, `..`, and `//`. The returned path — and `cwd` — are always
    /// canonical; display translation happens only at the print edges.
    fn resolve(&self, path: &str) -> String {
        let canon = path_style::to_canonical(path, self.kind, self.style);
        let combined = if canon.starts_with('/') {
            canon
        } else {
            join(&self.cwd, &canon)
        };
        normalize_path(&combined)
    }
}

/// Where the interactive shell persists its command history. `~/.fstool_history`
/// on Unix (via `$HOME`), `%USERPROFILE%\.fstool_history` on Windows. Returns
/// `None` when neither home variable is set, in which case history is
/// session-only.
#[cfg(feature = "readline")]
fn history_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(std::path::Path::new(&home).join(".fstool_history"))
}

fn split_cmd(line: &str) -> (&str, &str) {
    match line.find(char::is_whitespace) {
        Some(i) => (&line[..i], line[i..].trim()),
        None => (line, ""),
    }
}

/// Create a host symlink at `dest` pointing at `target`. Removes any existing
/// file at `dest` first (symlink creation fails if the path exists). On
/// non-unix platforms symlinks aren't created — returns `Unsupported`.
fn write_host_symlink(target: &str, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        if dest.symlink_metadata().is_ok() {
            std::fs::remove_file(dest)?;
        }
        std::os::unix::fs::symlink(target, dest)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        Err(fstool::Error::Unsupported(format!(
            "get: cannot create symlink {} on this platform",
            dest.display()
        )))
    }
}

fn join(base: &str, rel: &str) -> String {
    if base.ends_with('/') {
        format!("{base}{rel}")
    } else {
        format!("{base}/{rel}")
    }
}

/// Collapse `.`, `..`, and empty segments into an absolute, normalised
/// path. `..` past root is a no-op.
pub fn normalize_path(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    if out.is_empty() {
        "/".into()
    } else {
        format!("/{}", out.join("/"))
    }
}

// ---------- helpers for `find` / `grep` ----------

/// A `find` result row: the resolved path plus the metadata needed for
/// `-sort` and `-l` (long) output.
struct Hit {
    path: String,
    size: u64,
    mtime: u32,
}

/// `find -sort` key.
#[derive(Clone, Copy)]
enum SortKey {
    Mtime,
    Size,
    Name,
}

/// The single-letter `find -type` code for an entry kind (`?` for unknown).
fn kind_type_letter(kind: fstool::fs::EntryKind) -> char {
    use fstool::fs::EntryKind::{Block, Char, Dir, Fifo, Regular, Socket, Symlink, Unknown};
    match kind {
        Regular => 'f',
        Dir => 'd',
        Symlink => 'l',
        Char => 'c',
        Block => 'b',
        Fifo => 'p',
        Socket => 's',
        Unknown => '?',
    }
}

/// Current wall-clock time as unix epoch seconds (`0` if the clock is before
/// the epoch, which never happens in practice).
fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse a `find -newer`/`-older` time spec into unix epoch seconds. Accepts a
/// bare epoch integer, a relative `N{s,m,h,d,w}` ("that long ago", e.g. `7d`),
/// or an ISO `YYYY-MM-DD` date at 00:00 UTC.
fn parse_timespec(s: &str) -> Result<u64> {
    let s = s.trim();
    let bad = || fstool::Error::InvalidArgument(format!("find: bad time {s:?}"));
    if s.is_empty() {
        return Err(bad());
    }
    let b = s.as_bytes();
    // ISO date: YYYY-MM-DD
    if s.len() == 10 && b[4] == b'-' && b[7] == b'-' {
        let y: i64 = s[0..4].parse().map_err(|_| bad())?;
        let m: i64 = s[5..7].parse().map_err(|_| bad())?;
        let d: i64 = s[8..10].parse().map_err(|_| bad())?;
        if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
            return Err(bad());
        }
        let days = days_from_civil(y, m, d);
        return u64::try_from(days * 86400).map_err(|_| bad());
    }
    // Relative: N followed by a unit suffix.
    let last = *b.last().unwrap();
    if matches!(last, b's' | b'm' | b'h' | b'd' | b'w') {
        let n: u64 = s[..s.len() - 1].parse().map_err(|_| bad())?;
        let unit = match last {
            b's' => 1,
            b'm' => 60,
            b'h' => 3600,
            b'd' => 86400,
            b'w' => 604_800,
            _ => unreachable!(),
        };
        return Ok(now_epoch().saturating_sub(n * unit));
    }
    // Bare epoch seconds.
    s.parse::<u64>().map_err(|_| bad())
}

/// Days from the unix epoch (1970-01-01) to a civil date, using Howard
/// Hinnant's `days_from_civil` algorithm. Valid for the Gregorian calendar.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Match a basename `s` against a `*`/`?` glob `pat` (byte-wise, case-sensitive).
fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut si) = (0usize, 0usize);
    let (mut star, mut mark): (Option<usize>, usize) = (None, 0);
    while si < s.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == s[si]) {
            p += 1;
            si += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = Some(p);
            mark = si;
            p += 1;
        } else if let Some(sp) = star {
            p = sp + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// Treat content as binary (→ hexdump output) if it carries a NUL byte or
/// isn't valid UTF-8 — the same heuristic GNU grep uses to switch modes.
fn is_binary(data: &[u8]) -> bool {
    data.contains(&0) || std::str::from_utf8(data).is_err()
}

#[inline]
fn fold(b: u8, ci: bool) -> u8 {
    if ci { b.to_ascii_lowercase() } else { b }
}

/// All non-overlapping start offsets of `needle` in `hay` (ASCII-case-folded
/// when `ci`). Empty needle yields no hits.
fn find_all(hay: &[u8], needle: &[u8], ci: bool) -> Vec<usize> {
    let mut hits = Vec::new();
    let n = needle.len();
    if n == 0 || n > hay.len() {
        return hits;
    }
    let mut i = 0;
    while i + n <= hay.len() {
        if (0..n).all(|j| fold(hay[i + j], ci) == fold(needle[j], ci)) {
            hits.push(i);
            i += n; // non-overlapping
        } else {
            i += 1;
        }
    }
    hits
}

/// grep behaviour flags, threaded into the per-file printers.
#[derive(Clone, Copy)]
struct GrepOpts {
    ci: bool,
    numbers: bool,
    invert: bool,
    list: bool,
    count: bool,
    show_name: bool,
}

/// Print matching lines of a text file (grep style). Honours `-v` (invert),
/// `-l` (name only), and `-c` (count); `-l` takes precedence over `-c`.
fn grep_text(
    name: &str,
    data: &[u8],
    needle: &[u8],
    o: GrepOpts,
    out: &mut dyn Write,
) -> Result<()> {
    // Split into lines, dropping the empty segment a trailing newline produces
    // (so a file of N newline-terminated lines counts as N, not N+1). An empty
    // file has zero lines.
    let lines: Vec<&[u8]> = if data.is_empty() {
        Vec::new()
    } else {
        data.strip_suffix(b"\n")
            .unwrap_or(data)
            .split(|&b| b == b'\n')
            .collect()
    };
    // -l / -c only need a verdict per line, not the text.
    if o.list || o.count {
        let mut n = 0usize;
        for line in &lines {
            if interrupted() {
                break;
            }
            if find_all(line, needle, o.ci).is_empty() == o.invert {
                n += 1;
            }
        }
        let name = crate::safety::sanitize_name(name);
        if o.list {
            if n > 0 {
                writeln!(out, "{name}")?;
            }
        } else if o.show_name {
            writeln!(out, "{name}:{n}")?;
        } else {
            writeln!(out, "{n}")?;
        }
        return Ok(());
    }
    // Filenames are image-supplied; escape control bytes so a crafted name
    // can't inject terminal escapes. Matched line content is left verbatim.
    let name = crate::safety::sanitize_name(name);
    for (i, line) in lines.iter().enumerate() {
        if interrupted() {
            break;
        }
        if find_all(line, needle, o.ci).is_empty() != o.invert {
            continue;
        }
        let text = String::from_utf8_lossy(line);
        let text = text.strip_suffix('\r').unwrap_or(&text);
        match (o.show_name, o.numbers) {
            (true, true) => writeln!(out, "{name}:{}:{text}", i + 1)?,
            (true, false) => writeln!(out, "{name}:{text}")?,
            (false, true) => writeln!(out, "{}:{text}", i + 1)?,
            (false, false) => writeln!(out, "{text}")?,
        }
    }
    Ok(())
}

/// Print the rows of a binary file that contain a match, as `hexdump -C`
/// output. Non-contiguous match clusters are separated by a `*` line. `-l`
/// prints just the name and `-c` the match count; `-v`/`-n` don't apply to
/// binary output and are ignored.
fn grep_binary(
    name: &str,
    data: &[u8],
    needle: &[u8],
    o: GrepOpts,
    out: &mut dyn Write,
) -> Result<()> {
    let hits = find_all(data, needle, o.ci);
    if hits.is_empty() {
        return Ok(());
    }
    // Image-supplied filename: escape control bytes before printing.
    let name = crate::safety::sanitize_name(name);
    if o.list {
        writeln!(out, "{name}")?;
        return Ok(());
    }
    if o.count {
        if o.show_name {
            writeln!(out, "{name}:{}", hits.len())?;
        } else {
            writeln!(out, "{}", hits.len())?;
        }
        return Ok(());
    }
    if o.show_name {
        writeln!(
            out,
            "{name}: binary file, {} match(es) shown as hexdump -C:",
            hits.len()
        )?;
    }
    // The set of 16-byte rows that any match touches.
    let mut rows: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for &off in &hits {
        let end = off + needle.len();
        for r in (off / 16)..=((end - 1) / 16) {
            rows.insert(r);
        }
    }
    let mut prev: Option<usize> = None;
    for &row in &rows {
        if interrupted() {
            break;
        }
        if let Some(p) = prev
            && row != p + 1
        {
            writeln!(out, "*")?;
        }
        let base = row * 16;
        let chunk = &data[base..(base + 16).min(data.len())];
        hexdump_line(base, chunk, out)?;
        prev = Some(row);
    }
    Ok(())
}

/// One `hexdump -C` row: `OFFSET  xx xx … xx  xx … xx  |ascii|`.
fn hexdump_line(base: usize, chunk: &[u8], out: &mut dyn Write) -> Result<()> {
    let mut hex = String::with_capacity(50);
    for i in 0..16 {
        if i == 8 {
            hex.push(' ');
        }
        if i < chunk.len() {
            hex.push_str(&format!("{:02x} ", chunk[i]));
        } else {
            hex.push_str("   ");
        }
    }
    let ascii: String = chunk
        .iter()
        .map(|&b| {
            if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    writeln!(out, "{base:08x}  {hex} |{ascii}|")?;
    Ok(())
}

// ---------- formatting helpers for `cmd_info` ----------

/// Human-readable name for a [`fstool::fs::EntryKind`].
fn fmt_kind(kind: fstool::fs::EntryKind) -> &'static str {
    use fstool::fs::EntryKind;
    match kind {
        EntryKind::Regular => "regular file",
        EntryKind::Dir => "directory",
        EntryKind::Symlink => "symbolic link",
        EntryKind::Char => "character device",
        EntryKind::Block => "block device",
        EntryKind::Fifo => "fifo",
        EntryKind::Socket => "socket",
        EntryKind::Unknown => "unknown",
    }
}

/// Render POSIX permission bits in the `ls -l` shape — leading
/// type byte, three rwx triples, setuid/setgid/sticky overlays.
fn fmt_mode(kind: fstool::fs::EntryKind, mode: u16) -> String {
    use fstool::fs::EntryKind;
    let mut s = String::with_capacity(10);
    s.push(match kind {
        EntryKind::Regular => '-',
        EntryKind::Dir => 'd',
        EntryKind::Symlink => 'l',
        EntryKind::Char => 'c',
        EntryKind::Block => 'b',
        EntryKind::Fifo => 'p',
        EntryKind::Socket => 's',
        EntryKind::Unknown => '?',
    });
    for shift in [6u16, 3, 0] {
        let bits = (mode >> shift) & 0o7;
        s.push(if bits & 0o4 != 0 { 'r' } else { '-' });
        s.push(if bits & 0o2 != 0 { 'w' } else { '-' });
        s.push(if bits & 0o1 != 0 { 'x' } else { '-' });
    }
    // setuid/setgid/sticky overlay on the x slots.
    let bytes: Vec<u8> = s.bytes().collect();
    let mut bytes = bytes;
    if mode & 0o4000 != 0 {
        bytes[3] = if bytes[3] == b'x' { b's' } else { b'S' };
    }
    if mode & 0o2000 != 0 {
        bytes[6] = if bytes[6] == b'x' { b's' } else { b'S' };
    }
    if mode & 0o1000 != 0 {
        bytes[9] = if bytes[9] == b'x' { b't' } else { b'T' };
    }
    String::from_utf8(bytes).unwrap()
}

/// Format a Unix epoch second count as an ISO-8601 UTC string
/// (`YYYY-MM-DDTHH:MM:SSZ`). Uses Hinnant's `civil_from_days`
/// algorithm — no external date crate, valid for all positive `u32`
/// timestamps (up to year 2106).
fn fmt_unix_utc(t: u32) -> String {
    let total = t as i64;
    let days = total.div_euclid(86_400);
    let sod = total.rem_euclid(86_400) as u32;
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = z - era * 146_097; // [0, 146097)
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    let h = sod / 3600;
    let mn = (sod / 60) % 60;
    let s = sod % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mn:02}:{s:02}Z")
}

/// Format an xattr value for display. Pure-ASCII (printable + tab/LF)
/// renders as a quoted string; otherwise prints the byte length plus a
/// hex preview of the first 16 bytes. Keeps single-line so the
/// `name = value` layout stays scannable.
fn fmt_xattr_value(value: &[u8]) -> String {
    let is_printable = !value.is_empty()
        && value
            .iter()
            .all(|&b| matches!(b, b'\t' | b'\n' | 0x20..=0x7e));
    if is_printable {
        // Strip a trailing newline so the line stays tight.
        let s = std::str::from_utf8(value).unwrap();
        let s = s.strip_suffix('\n').unwrap_or(s);
        return format!("{:?}", s);
    }
    let n = value.len();
    let preview_len = n.min(16);
    let mut hex = String::with_capacity(preview_len * 3);
    for (i, b) in value[..preview_len].iter().enumerate() {
        if i > 0 {
            hex.push(' ');
        }
        hex.push_str(&format!("{b:02x}"));
    }
    if n > preview_len {
        format!("<{n} bytes> {hex}…")
    } else {
        format!("<{n} bytes> {hex}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_roots() {
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("///"), "/");
    }

    #[test]
    fn find_all_offsets_and_ci() {
        assert_eq!(find_all(b"abcabc", b"bc", false), vec![1, 4]);
        assert_eq!(find_all(b"aaaa", b"aa", false), vec![0, 2]); // non-overlapping
        assert_eq!(find_all(b"AbC", b"abc", true), vec![0]);
        assert!(find_all(b"abc", b"abc", false).contains(&0));
        assert!(find_all(b"abc", b"", false).is_empty());
        assert!(find_all(b"ab", b"abc", false).is_empty());
    }

    #[test]
    fn is_binary_heuristic() {
        assert!(!is_binary(b"plain text\nwith newline\n"));
        assert!(is_binary(b"has\0nul"));
        assert!(is_binary(&[0xff, 0xfe, 0x00, 0x01])); // invalid utf-8 + nul
        assert!(is_binary(&[0xc3, 0x28])); // invalid utf-8 (no nul)
    }

    fn gopts(ci: bool, numbers: bool, show_name: bool) -> GrepOpts {
        GrepOpts {
            ci,
            numbers,
            show_name,
            invert: false,
            list: false,
            count: false,
        }
    }

    #[test]
    fn grep_text_formats() {
        let data = b"hello world\nsecond\nHELLO again\n";
        let mut out = Vec::new();
        grep_text("f", data, b"hello", gopts(false, true, true), &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "f:1:hello world\n");
        // case-insensitive catches both lines
        let mut out = Vec::new();
        grep_text("f", data, b"hello", gopts(true, false, false), &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "hello world\nHELLO again\n"
        );
    }

    #[test]
    fn grep_text_invert_count_list() {
        let data = b"hello world\nsecond\nHELLO again\n";
        // -v: lines NOT containing "hello" (case-sensitive) — "second" + "HELLO again".
        let mut out = Vec::new();
        let mut o = gopts(false, false, false);
        o.invert = true;
        grep_text("f", data, b"hello", o, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "second\nHELLO again\n");
        // -c with a name prefix counts matching lines.
        let mut out = Vec::new();
        let mut o = gopts(true, false, true);
        o.count = true;
        grep_text("f", data, b"hello", o, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "f:2\n");
        // -l prints the name once when there's a match.
        let mut out = Vec::new();
        let mut o = gopts(false, false, true);
        o.list = true;
        grep_text("f", data, b"hello", o, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "f\n");
    }

    #[test]
    fn grep_binary_emits_hexdump_rows() {
        // 16 bytes/row; "NEEDLE" lands in row 1 (offset 0x10).
        let mut data = vec![0u8; 16];
        data.extend_from_slice(b"xx NEEDLE xx\x00\x00\x00\x00");
        let mut out = Vec::new();
        grep_binary("b", &data, b"NEEDLE", gopts(false, false, true), &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("binary file"));
        assert!(s.contains("00000010 "), "row offset missing:\n{s}");
        assert!(s.contains("|xx NEEDLE xx"), "ascii pane missing:\n{s}");
        // -l on a binary match prints just the name.
        let mut out = Vec::new();
        let mut o = gopts(false, false, true);
        o.list = true;
        grep_binary("b", &data, b"NEEDLE", o, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "b\n");
    }

    #[test]
    fn hexdump_line_layout() {
        let mut out = Vec::new();
        hexdump_line(0, b"hello world\n", &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        // offset, hex bytes, gap after 8th byte, and ascii pane with '.' for \n.
        assert!(s.starts_with("00000000  68 65 6c 6c 6f 20 77 6f  72 6c 64 0a"));
        assert!(s.trim_end().ends_with("|hello world.|"));
    }

    #[test]
    fn glob_match_cases() {
        let g = |p: &str, s: &str| glob_match(p.as_bytes(), s.as_bytes());
        assert!(g("data.txt", "data.txt"));
        assert!(g("notes.txt", "notes.txt"));
        assert!(g("*.txt", "notes.txt"));
        assert!(g("*.txt", "data.txt"));
        assert!(g("n*", "notes.txt"));
        assert!(g("*.*", "notes.txt"));
        assert!(g("notes*", "notes.txt"));
        assert!(g("?otes.txt", "notes.txt"));
        assert!(!g("*.txt", "blob.bin"));
        assert!(!g("data.txt", "notes.txt"));
        assert!(g("*", "anything"));
        assert!(g("", ""));
        assert!(!g("", "x"));
    }

    #[test]
    fn normalize_collapses_dotdot() {
        assert_eq!(normalize_path("/a/b/../c"), "/a/c");
        assert_eq!(normalize_path("/a/../.."), "/");
        assert_eq!(normalize_path("/./a/./b/"), "/a/b");
    }

    #[test]
    fn split_cmd_simple() {
        assert_eq!(split_cmd("ls"), ("ls", ""));
        assert_eq!(split_cmd("ls /etc"), ("ls", "/etc"));
        assert_eq!(split_cmd("put a b"), ("put", "a b"));
    }

    #[test]
    fn fmt_mode_renders_ls_l_layout() {
        use fstool::fs::EntryKind;
        assert_eq!(super::fmt_mode(EntryKind::Regular, 0o644), "-rw-r--r--");
        assert_eq!(super::fmt_mode(EntryKind::Dir, 0o755), "drwxr-xr-x");
        assert_eq!(super::fmt_mode(EntryKind::Symlink, 0o777), "lrwxrwxrwx");
        assert_eq!(super::fmt_mode(EntryKind::Char, 0o600), "crw-------");
        assert_eq!(super::fmt_mode(EntryKind::Block, 0o660), "brw-rw----");
        // Setuid / setgid / sticky overlays.
        assert_eq!(super::fmt_mode(EntryKind::Regular, 0o4755), "-rwsr-xr-x");
        assert_eq!(super::fmt_mode(EntryKind::Regular, 0o4644), "-rwSr--r--");
        assert_eq!(super::fmt_mode(EntryKind::Dir, 0o1755), "drwxr-xr-t");
    }

    #[test]
    fn fmt_unix_utc_known_epochs() {
        // The Unix epoch.
        assert_eq!(super::fmt_unix_utc(0), "1970-01-01T00:00:00Z");
        // 2001-09-09T01:46:40Z — the iconic 1e9 timestamp.
        assert_eq!(super::fmt_unix_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        // 2023-11-14T22:13:20Z — the 1.7e9 mark.
        assert_eq!(super::fmt_unix_utc(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn parse_timespec_forms() {
        // Bare epoch.
        assert_eq!(super::parse_timespec("1700000000").unwrap(), 1_700_000_000);
        // ISO date at 00:00 UTC (verified against fmt_unix_utc).
        let t = super::parse_timespec("2023-11-14").unwrap();
        assert_eq!(super::fmt_unix_utc(t as u32), "2023-11-14T00:00:00Z");
        // Relative ages are "now minus N units" — check the deltas, not the clock.
        let now = super::now_epoch();
        let d7 = super::parse_timespec("7d").unwrap();
        assert!((now - d7).abs_diff(7 * 86400) <= 1);
        let h12 = super::parse_timespec("12h").unwrap();
        assert!((now - h12).abs_diff(12 * 3600) <= 1);
        // Garbage is rejected.
        assert!(super::parse_timespec("").is_err());
        assert!(super::parse_timespec("nope").is_err());
        assert!(super::parse_timespec("2023-13-01").is_err());
    }

    #[test]
    fn days_from_civil_anchors() {
        assert_eq!(super::days_from_civil(1970, 1, 1), 0);
        assert_eq!(super::days_from_civil(1970, 1, 2), 1);
        assert_eq!(super::days_from_civil(1969, 12, 31), -1);
        // 2000-03-01 is 11017 days after the epoch.
        assert_eq!(super::days_from_civil(2000, 3, 1), 11017);
    }

    #[test]
    fn kind_type_letters() {
        use fstool::fs::EntryKind::{Block, Char, Dir, Fifo, Regular, Socket, Symlink};
        assert_eq!(super::kind_type_letter(Regular), 'f');
        assert_eq!(super::kind_type_letter(Dir), 'd');
        assert_eq!(super::kind_type_letter(Symlink), 'l');
        assert_eq!(super::kind_type_letter(Block), 'b');
        assert_eq!(super::kind_type_letter(Char), 'c');
        assert_eq!(super::kind_type_letter(Fifo), 'p');
        assert_eq!(super::kind_type_letter(Socket), 's');
    }

    /// Format a tiny ext image in memory with a couple of nested dirs and
    /// return the device plus a mutating `Shell` over it.
    fn ext_shell() -> (fstool::block::MemoryBackend, Shell) {
        use fstool::fs::ext::{Ext, FormatOpts};
        let opts = FormatOpts {
            inodes_count: 64,
            ..FormatOpts::default()
        };
        let mut dev =
            fstool::block::MemoryBackend::new(opts.blocks_count as u64 * opts.block_size as u64);
        {
            let mut ext = Ext::format_with(&mut dev, &opts).unwrap();
            ext.flush(&mut dev).unwrap();
        }
        let fs = AnyFs::open_writable(&mut dev).unwrap();
        let mut sh = Shell::new(fs, PathStyle::Unix);
        let mut sink = Vec::new();
        sh.cmd_mkdir(&mut dev, "/a", &mut sink).unwrap();
        sh.cmd_mkdir(&mut dev, "/a/b", &mut sink).unwrap();
        (dev, sh)
    }

    #[test]
    fn get_roundtrips_file_dir_and_dest_modes() {
        let (mut dev, mut sh) = ext_shell();
        let tmp = tempfile::tempdir().unwrap();
        let mut sink = Vec::new();

        // Stage a file on the host, put it into the image, then get it back.
        let host_src = tmp.path().join("hello.txt");
        std::fs::write(&host_src, b"image contents\n").unwrap();
        sh.cmd_put(
            &mut dev,
            &format!("{} /hello.txt", host_src.display()),
            &mut sink,
        )
        .unwrap();

        // get with an explicit target path.
        let out = tmp.path().join("out.txt");
        sh.cmd_get(
            &mut dev,
            &format!("/hello.txt {}", out.display()),
            &mut sink,
        )
        .unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"image contents\n");

        // get into an existing directory appends the basename.
        let into = tmp.path().join("into");
        std::fs::create_dir(&into).unwrap();
        sh.cmd_get(
            &mut dev,
            &format!("/hello.txt {}", into.display()),
            &mut sink,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(into.join("hello.txt")).unwrap(),
            b"image contents\n"
        );

        // Recursive get of a directory: put a file under /a, then pull /a out.
        sh.cmd_put(
            &mut dev,
            &format!("{} /a/f.txt", host_src.display()),
            &mut sink,
        )
        .unwrap();
        let adst = tmp.path().join("a_copy");
        sh.cmd_get(&mut dev, &format!("/a {}", adst.display()), &mut sink)
            .unwrap();
        assert_eq!(
            std::fs::read(adst.join("f.txt")).unwrap(),
            b"image contents\n"
        );
        // The nested empty dir /a/b is recreated too.
        assert!(adst.join("b").is_dir());
    }

    #[test]
    fn get_missing_source_errors() {
        let (mut dev, mut sh) = ext_shell();
        let tmp = tempfile::tempdir().unwrap();
        let mut sink = Vec::new();
        let out = tmp.path().join("x");
        assert!(
            sh.cmd_get(&mut dev, &format!("/nope.txt {}", out.display()), &mut sink)
                .is_err()
        );
    }

    #[test]
    fn preload_populates_cache_and_marks_done() {
        let (mut dev, mut sh) = ext_shell();
        sh.enable_cache();
        sh.preload(&mut dev).unwrap();
        let c = sh.cache.as_ref().expect("cache on");
        assert!(c.preloaded);
        // Every directory we walked is cached, including the nested ones.
        assert!(c.dirs.contains_key("/"));
        assert!(c.dirs.contains_key("/a"));
        assert!(c.dirs.contains_key("/a/b"));
        // And the attrs of the entries under them.
        assert!(c.attrs.contains_key("/a"));
        assert!(c.attrs.contains_key("/a/b"));
    }

    #[test]
    fn cache_serves_after_device_would_change() {
        // After preload, a cached `list` returns the snapshot even if we then
        // (separately) mutate the device behind the cache's back — proving it
        // served from RAM, not a fresh parse.
        let (mut dev, mut sh) = ext_shell();
        sh.enable_cache();
        sh.preload(&mut dev).unwrap();
        let before = sh.list(&mut dev, "/").unwrap();
        // Mutate the underlying fs directly (not through the shell, so the
        // cache isn't invalidated).
        sh.fs.mkdir(&mut dev, "/zzz").unwrap();
        sh.fs.flush(&mut dev).unwrap();
        let cached = sh.list(&mut dev, "/").unwrap();
        assert_eq!(
            before.len(),
            cached.len(),
            "cached listing should not see the out-of-band mkdir"
        );
        assert!(!cached.iter().any(|e| e.name == "zzz"));
    }

    #[test]
    fn invalidate_after_mutation_refills_lazily() {
        let (mut dev, mut sh) = ext_shell();
        sh.enable_cache();
        sh.preload(&mut dev).unwrap();
        // A shell mutation must invalidate the cache.
        let mut sink = Vec::new();
        sh.cmd_mkdir(&mut dev, "/fresh", &mut sink).unwrap();
        assert!(!sh.cache.as_ref().unwrap().preloaded);
        assert!(sh.cache.as_ref().unwrap().dirs.is_empty());
        // The next read lazily refills and now sees the new directory.
        let root = sh.list(&mut dev, "/").unwrap();
        assert!(root.iter().any(|e| e.name == "fresh"));
        assert!(sh.cache.as_ref().unwrap().dirs.contains_key("/"));
    }

    #[test]
    fn no_cache_means_no_map() {
        let (mut dev, mut sh) = ext_shell();
        // Without enable_cache, reads still work and nothing is cached.
        assert!(sh.cache.is_none());
        let _ = sh.list(&mut dev, "/").unwrap();
        assert!(sh.cache.is_none());
        // preload is a no-op.
        sh.preload(&mut dev).unwrap();
        assert!(sh.cache.is_none());
    }

    #[test]
    fn fmt_xattr_value_chooses_string_or_hex() {
        // Printable ASCII renders as a quoted string.
        assert_eq!(super::fmt_xattr_value(b"text/plain"), r#""text/plain""#);
        // Trailing newline gets stripped so the output stays single-line.
        assert_eq!(super::fmt_xattr_value(b"v1\n"), r#""v1""#);
        // Non-printable bytes fall back to <N bytes> + hex preview.
        let mut v = b"\x01\x00\x04\x80".to_vec();
        assert_eq!(super::fmt_xattr_value(&v), "<4 bytes> 01 00 04 80");
        // Long values truncate after 16 bytes with a `…` marker.
        v = (0u8..=31).collect();
        let s = super::fmt_xattr_value(&v);
        assert!(s.starts_with("<32 bytes> "), "{s}");
        assert!(s.ends_with('…'), "{s}");
    }
}
