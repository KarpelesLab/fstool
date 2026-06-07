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
//!   rm PATH             remove a file or empty directory
//!   mkdir PATH          create an empty directory
//!   info [PATH]         no arg → image summary; with PATH → per-file
//!                       metadata (kind/mode/owner/size/blocks/nlink
//!                       /inode/atime/mtime/ctime/rdev) plus any
//!                       extended attributes (fs-specific properties
//!                       come through here: NTFS DOS attrs, ADS,
//!                       security descriptors; ext / squashfs xattrs;
//!                       HFS+ Finder info; …)
//!   find [PATH] [-name GLOB] [-type f|d]
//!                       recursively list paths (default: cwd), optionally
//!                       filtered by a `*`/`?` name glob and/or entry type
//!   grep [-i] [-n] [-r] PATTERN [PATH...]
//!                       search files for the literal PATTERN; text files
//!                       print matching lines, binary files print the
//!                       matching rows as `hexdump -C` output
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
        }
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
        let body = format!(
            "ls [PATH]           list a directory (default: cwd)
pwd                 print the current directory
cd [PATH]           change directory (no arg → /)
cat PATH            print a file's contents to stdout
put HOST [DEST]     copy a host file or directory into the image
rm PATH             remove a file or empty directory
mkdir PATH          create an empty directory
info [PATH]         no arg → image summary; with PATH → file metadata
                    (kind/mode/owner/size/blocks/nlink/inode/atime/mtime
                    /ctime/rdev) plus any extended attributes
find [PATH] [-name GLOB] [-type f|d]
                    recursively list paths under PATH (default: cwd),
                    optionally filtered by name glob (* ?) and/or type
grep [-i] [-n] [-r] PATTERN [PATH...]
                    search files for the literal PATTERN (default PATH: cwd
                    with -r). -i case-insensitive, -n line numbers, -r recurse.
                    Binary files print their matches as `hexdump -C` rows
                    (Ctrl-C cancels a running find/grep without leaving the shell)
help | ?            print this help
quit | exit         leave{ro_note}\n"
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
        let entries = self.fs.list(dev, &target)?;
        for e in &entries {
            let suffix = match e.kind {
                fstool::fs::EntryKind::Dir => "/",
                fstool::fs::EntryKind::Symlink => "@",
                _ => "",
            };
            writeln!(
                output,
                "{}{}",
                path_style::display_name(&e.name, self.kind, self.style),
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
        self.fs.list(dev, &target)?;
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
        writeln!(output, "put {} → {dest}", host.display())?;
        Ok(())
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
        let attrs = self.fs.getattr(dev, Path::new(&path))?;

        writeln!(output, "path:   {path}")?;
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
            writeln!(output, "target: {tgt}")?;
        }

        // Extended attributes — fs-specific metadata in a generic shape.
        // Empty xattr lists are common (most ext images, most files),
        // so omit the section entirely when none.
        let xattrs = self.fs.list_xattrs(dev, Path::new(&path))?;
        if !xattrs.is_empty() {
            writeln!(output)?;
            writeln!(output, "xattrs ({}):", xattrs.len())?;
            for xa in &xattrs {
                writeln!(output, "  {:<28} = {}", xa.name, fmt_xattr_value(&xa.value))?;
            }
        }
        Ok(())
    }

    /// `find [PATH] [-name GLOB] [-type f|d]` — recursively print every path
    /// under PATH (default cwd), optionally filtered by a basename glob and/or
    /// an entry type. Paths print in the active display style.
    fn cmd_find(
        &mut self,
        dev: &mut dyn BlockDevice,
        arg: &str,
        output: &mut impl Write,
    ) -> Result<()> {
        let mut start: Option<String> = None;
        let mut name: Option<String> = None;
        let mut type_filter: Option<char> = None;
        let mut toks = arg.split_whitespace();
        while let Some(tok) = toks.next() {
            match tok {
                "-name" => {
                    name = Some(
                        toks.next()
                            .ok_or_else(|| {
                                fstool::Error::InvalidArgument("find: -name needs a pattern".into())
                            })?
                            .to_string(),
                    );
                }
                "-type" => {
                    let t = toks.next().ok_or_else(|| {
                        fstool::Error::InvalidArgument("find: -type needs f or d".into())
                    })?;
                    type_filter = match t {
                        "f" => Some('f'),
                        "d" => Some('d'),
                        other => {
                            return Err(fstool::Error::InvalidArgument(format!(
                                "find: -type {other:?} (use f or d)"
                            )));
                        }
                    };
                }
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

        let matches = |entry_name: &str, kind: fstool::fs::EntryKind| -> bool {
            let type_ok = match type_filter {
                Some('f') => matches!(kind, fstool::fs::EntryKind::Regular),
                Some('d') => matches!(kind, fstool::fs::EntryKind::Dir),
                _ => true,
            };
            let name_ok = name
                .as_deref()
                .map(|g| glob_match(g.as_bytes(), entry_name.as_bytes()))
                .unwrap_or(true);
            type_ok && name_ok
        };
        let print = |path: &str, output: &mut dyn Write| -> Result<()> {
            writeln!(
                output,
                "{}",
                path_style::display_path(path, self.kind, self.style)
            )?;
            Ok(())
        };

        // Evaluate the start path itself, then recurse if it's a directory.
        let start_kind = self.fs.getattr(dev, Path::new(&start))?.kind;
        let start_name = start.rsplit('/').next().unwrap_or("");
        if matches(start_name, start_kind) {
            print(&start, output)?;
        }
        if !matches!(start_kind, fstool::fs::EntryKind::Dir) {
            return Ok(());
        }

        let mut stack = vec![start];
        while let Some(dir) = stack.pop() {
            if interrupted() {
                break;
            }
            let entries = self.fs.list(dev, &dir)?;
            for e in entries {
                if interrupted() {
                    break;
                }
                if e.name == "." || e.name == ".." {
                    continue; // never recurse into the self/parent links
                }
                let child = join(&dir, &e.name);
                if matches(&e.name, e.kind) {
                    print(&child, output)?;
                }
                if matches!(e.kind, fstool::fs::EntryKind::Dir) {
                    stack.push(child);
                }
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
        let mut pattern: Option<String> = None;
        let mut paths: Vec<String> = Vec::new();
        for tok in arg.split_whitespace() {
            if pattern.is_none() && tok.starts_with('-') && tok.len() > 1 {
                for f in tok[1..].chars() {
                    match f {
                        'i' => ci = true,
                        'n' => numbers = true,
                        'r' | 'R' => recurse = true,
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
            match self.fs.getattr(dev, Path::new(&p))?.kind {
                fstool::fs::EntryKind::Dir => {
                    if !recurse {
                        writeln!(output, "grep: {p}: is a directory (use -r)")?;
                        continue;
                    }
                    let mut stack = vec![p];
                    while let Some(dir) = stack.pop() {
                        if interrupted() {
                            break;
                        }
                        for e in self.fs.list(dev, &dir)? {
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
                _ => writeln!(output, "grep: {p}: not a regular file")?,
            }
        }
        let show_name = files.len() > 1 || recurse;

        const CAP: u64 = 256 * 1024 * 1024;
        for path in files {
            if interrupted() {
                break;
            }
            let size = self.fs.getattr(dev, Path::new(&path))?.size;
            if size > CAP {
                writeln!(
                    output,
                    "grep: {path}: file too large ({size} bytes), skipped"
                )?;
                continue;
            }
            let mut data = Vec::with_capacity(size as usize);
            self.fs.copy_file_to(dev, &path, &mut data)?;
            if is_binary(&data) {
                grep_binary(&path, &data, needle, ci, show_name, output)?;
            } else {
                grep_text(&path, &data, needle, ci, show_name, numbers, output)?;
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

/// Print matching lines of a text file (grep style).
fn grep_text(
    name: &str,
    data: &[u8],
    needle: &[u8],
    ci: bool,
    show_name: bool,
    numbers: bool,
    out: &mut dyn Write,
) -> Result<()> {
    for (i, line) in data.split(|&b| b == b'\n').enumerate() {
        if interrupted() {
            break;
        }
        if find_all(line, needle, ci).is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(line);
        let text = text.strip_suffix('\r').unwrap_or(&text);
        match (show_name, numbers) {
            (true, true) => writeln!(out, "{name}:{}:{text}", i + 1)?,
            (true, false) => writeln!(out, "{name}:{text}")?,
            (false, true) => writeln!(out, "{}:{text}", i + 1)?,
            (false, false) => writeln!(out, "{text}")?,
        }
    }
    Ok(())
}

/// Print the rows of a binary file that contain a match, as `hexdump -C`
/// output. Non-contiguous match clusters are separated by a `*` line.
fn grep_binary(
    name: &str,
    data: &[u8],
    needle: &[u8],
    ci: bool,
    show_name: bool,
    out: &mut dyn Write,
) -> Result<()> {
    let hits = find_all(data, needle, ci);
    if hits.is_empty() {
        return Ok(());
    }
    if show_name {
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

    #[test]
    fn grep_text_formats() {
        let data = b"hello world\nsecond\nHELLO again\n";
        let mut out = Vec::new();
        grep_text("f", data, b"hello", false, true, true, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "f:1:hello world\n");
        // case-insensitive catches both lines
        let mut out = Vec::new();
        grep_text("f", data, b"hello", true, false, false, &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "hello world\nHELLO again\n"
        );
    }

    #[test]
    fn grep_binary_emits_hexdump_rows() {
        // 16 bytes/row; "NEEDLE" lands in row 1 (offset 0x10).
        let mut data = vec![0u8; 16];
        data.extend_from_slice(b"xx NEEDLE xx\x00\x00\x00\x00");
        let mut out = Vec::new();
        grep_binary("b", &data, b"NEEDLE", false, true, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("binary file"));
        assert!(s.contains("00000010 "), "row offset missing:\n{s}");
        assert!(s.contains("|xx NEEDLE xx"), "ascii pane missing:\n{s}");
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
