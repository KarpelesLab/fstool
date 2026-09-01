# fstool

[![CI](https://github.com/KarpelesLab/fstool/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/fstool/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/fstool.svg)](https://crates.io/crates/fstool)
[![docs.rs](https://docs.rs/fstool/badge.svg)](https://docs.rs/fstool)

**Try it in your browser (no install): <https://karpeleslab.github.io/fstool/>**

Build, inspect, modify, and repack disk images and filesystem images.
In the spirit of `genext2fs`, but covering whole disks, multiple filesystems,
and round-tripping between formats — all from a TOML spec or directly from
the command line.

fstool ships as a Rust library (`fstool`) plus a thin CLI binary (`fstool`).
Public API is **unstable** until v0.5.

```sh
cargo install fstool
fstool create -t ext4 ./src -o out.img           # build an ext4 image from a dir
fstool create -t squashfs ./src -o out.sqsh \
       -O compression=zstd,block_size=128KiB     # FS-specific knobs via -O
fstool info out.img                              # what's inside
fstool ls   out.img /                            # walk it
fstool repack out.img out.tar                    # convert ext4 → tar (and back)
fstool repack base.tar patch.tar flat.tar        # OCI-style layer merge with .wh.* whiteouts
```

## Web UI (runs in your browser)

**▶ Live demo: <https://karpeleslab.github.io/fstool/>**

fstool also ships as a static, client-side web app. It builds images as well
as reads them: format a blank filesystem (ext2/3/4, FAT12/16/32, exFAT, NTFS,
XFS, HFS+, HFS, AFFS, F2FS, littlefs, GRF), or lay out an MBR/GPT disk with a
filesystem per partition, add files, and download the image — then keep
editing and download again. Or upload any archive or disk
image, browse what's inside, extract individual files, and convert the whole
thing to another format — **entirely in the browser**, with nothing uploaded.
It's fstool compiled to WebAssembly, driving the same readers/writers as the
CLI over an in-memory block device.

- Site: `web/` — a Vue 3 + Vite app (deployed to GitHub Pages by
  `.github/workflows/pages.yml`).
- Bindings: [`src/wasm.rs`](src/wasm.rs), compiled as the crate's `cdylib`
  behind the `wasm` feature (`--features wasm --target wasm32-unknown-unknown`).
- Library surface: [`fstool::memconv`](src/memconv.rs) — a byte-in / byte-out
  API (`probe(&[u8])`, `MemImage::open(Vec<u8>)`, `.list()`, `.read_file()`,
  `.convert(target) -> Vec<u8>`) built on the first-class in-memory
  [`MemoryBackend`](src/block/memory.rs). Use it from any host program to
  inspect or transcode an image without ever touching the filesystem:

  ```rust
  let mut img = fstool::memconv::MemImage::open(std::fs::read("in.tar.gz")?)?;
  let ext4 = img.convert("ext4")?;         // repack to an ext4 image, in RAM
  std::fs::write("out.img", ext4)?;
  ```

See [web/README.md](web/README.md) for the build and local-dev steps.

## Filesystem support

| Filesystem | Read | Write | In-place edits | Notes                                                                                                              |
|------------|------|-------|----------------|--------------------------------------------------------------------------------------------------------------------|
| ext2       | ✅    | ✅     | ✅              | byte-exact with `genext2fs` on the same input                                                                      |
| ext3       | ✅    | ✅     | ✅              | + JBD2 journal — real transactions on `open_file_rw` (Path A)                                                      |
| ext4       | ✅    | ✅     | ✅              | extents (read + write: any depth), FILETYPE, `metadata_csum`, xattrs, JBD2                                         |
| FAT12/16/32 | ✅    | ✅     | ✅              | one backend for all three widths; the flavour follows the data-cluster count, not the `fs_type` string. VFAT LFN entries, 8.3 short-name aliases. FAT12/16 use the fixed root region (sized by `-O root_entries=`, default 224 on floppy-sized media / 512 otherwise) and so cannot grow the root; validated against `fsck.vfat` + `mtools` both ways |
| exFAT      | ✅    | ✅     | ✅              | format + create + remove + flush + `open_file_rw`                                                                  |
| tar        | ✅    | ✅     | —              | ustar + PAX, `SCHILY.xattr.*` for xattrs; streaming-only                                                           |
| XFS        | ✅    | ✅     | ✅              | shortform + block / leaf / node + multi-level B-tree dirs + BMBT; leaf-form xattrs; real XLOG transactions (Path A); passes `xfs_repair -n` single + multi-AG |
| HFS+/HFSX  | ✅    | ✅     | ✅              | inline + extents-overflow, symlinks, hard links; decmpfs read (zlib types 3 + 4); **resource forks** (`cat --rsrc`, `resources`, `com.apple.ResourceFork` xattr); real journal (Path A); passes `fsck.hfsplus` |
| HFS        | ✅    | ✅     | ✅              | classic HFS (Mac OS ≤ 8): MDB + catalog/extents B-trees, MacRoman names, data + **resource** fork read; transparently unwraps **DiskCopy 4.2** images. **Write**: `create -t hfs` / `build` / `repack` generate fresh volumes, and `add` / `rm` / shell `put`/`mkdir` mutate an existing image in place (catalog rebuilt on flush) |
| AFFS       | ✅    | ✅     | ✅              | Amiga OFS/FFS (`.adf`): boot-block variant detect (`DOS\0`..`DOS\7`), hash-table dirs, file header + extension blocks, OFS (24-byte data headers) + FFS raw data, BCPL/Latin-1 names, Amiga 1978 epoch dates; read validated against real OFS/FFS Workbench volumes. **Write**: `create -t affs` / `-t ofs` / `build` / `repack` generate fresh OFS or FFS volumes (default DOS\3 FFS+INTL; `-O fstype=ofs,intl=false`), and `add` / `rm` / shell `put`/`mkdir` mutate an existing image **incrementally on disk** — only the affected blocks (volume bitmap, the parent directory's hash chain, and the new/removed file's header + data + extension blocks) are touched; untouched files keep their exact blocks, and RAM use is bounded by the bitmap, not file contents. Spec-conformant (block checksums + name-hash placement + bitmap, the invariants the Linux kernel `affs` driver enforces) |
| APFS       | ✅    | ✅     | 🚧             | **Read**: multi-level omap + fs-tree, directory listings + file extents, embedded xattrs, snapshots (read-only, single-leaf snap-meta). **Write**: format + `create_dir`/`create_file`/`create_symlink` + `chmod`/`chown`/`set_times`/`rename`/`unlink`/`link` via fresh COW checkpoints (spaceman with IP ring + SFQ free-queues), round-tripped through a real macOS mount. **Gaps**: in-place edits are whole-file overwrite (no partial-extent COW); `UF_COMPRESSED`/decmpfs files read as empty; encryption, sealed-volume integrity, Fusion tiering, and dstream-backed xattrs are refused; not yet `fsck_apfs`-clean |
| NTFS       | ✅    | ✅     | ✅              | MFT, attributes, $DATA + ADS, indexes; xattr map; multi-class `$Secure` ($SDS/$SDH/$SII); real `$LogFile` LFS records (Path A) |
| F2FS       | ✅    | ✅     | —              | CP / NAT / dnodes / inline data + dentries; writer passes `fsck.f2fs`; **build-once** — the writer serializes the whole FS from memory at flush, so a re-opened image is read-only (reports `Immutable`) |
| littlefs   | ✅    | ✅     | ✅              | The embedded-flash filesystem (`lfs2`, disk versions 2.0 + 2.1): metadata pairs with CRC-committed logs, CTZ skip-list files, inline small files, user attributes (surfaced as `user.littlefs.<type>` xattrs). Every mutation is a real littlefs commit, so `create` / `repack` / `add` / `rm` / `open_file_rw` all write images the reference C implementation mounts and keeps writing to — cross-validated both directions against `littlefs-python` (upstream `lfs.c`), including block-for-block agreement on which blocks are live. No symlinks, device nodes or POSIX metadata: the format has none |
| SquashFS   | ✅    | ✅     | —              | gzip / xz / lz4 / zstd / lzo / lzma via Cargo features; writer round-trips via `unsquashfs`; repack-only           |
| ISO 9660   | ✅    | ✅     | —              | PVD + Joliet (UCS-2) + Rock Ridge (PX/NM/SL/TF) + El Torito boot catalog; repack-only                              |
| GRF        | ✅    | ✅     | ✅              | Gravity Ragnarok Online archive — v0x102 / v0x103 / v0x200; permutation cipher (`MIXCRYPT` / `DES`); CP949 filenames |
| zip        | ✅    | ✅     | —              | central-directory index, ZIP64, Stored + Deflate, Unix mode/symlinks, UTF-8/Shift-JIS/EUC-JP filename detection; repack-only writer |
| cpio       | ✅    | ✅     | —              | newc / newc-crc / odc read; newc write; repack-only                                                              |
| ar         | ✅    | ✅     | —              | GNU + BSD long names (read), GNU write; flat (no directories); repack-only                                       |
| cab        | ✅    | —     | —              | Microsoft Cabinet read-only: Store / MSZIP / LZX / Quantum folders decode via `compcol` (cross-checked with `cabextract`). Spanned cabinets and creation are unsupported |
| lzx        | ✅    | —     | —              | Amiga LZX read-only: Store + LZX (mode 2) merged groups via `compcol::amiga_lzx`; container cross-checked with `unlzx`. Creation unsupported |
| rar        | ✅    | —     | —              | RAR5 read-only incl. **solid** archives (a sequential walk / `repack` decodes the group once): Store + compressed (no-filter / x86 E8E9) via `compcol::rar5`; cross-checked with `unrar`. RAR4, encryption, stored-in-solid, other filters and creation are unsupported |
| lha        | ✅    | —     | —              | LHA / LZH read-only: walks level-0/1/2 headers (long names + directories). `-lh0-` store decodes + is cross-checked with `lha`; the lh1/4/5/6/7 LZSS+Huffman methods list but read as `Unsupported` pending an `lha` codec in `compcol`. Creation unsupported |
| arc        | ✅    | —     | —              | SEA ARC read-only: walks the flat header chain. Stored methods (1 old / 2) decode; the compressed methods (RLE90 / squeeze / crunch / squash) list but read as `Unsupported` pending ARC codecs in `compcol`. Creation unsupported |
| sit        | ✅    | —     | —              | StuffIt read-only: classic `SIT!` container (data-fork indexing, folder markers). Method 0 (store) decodes; compressed methods + StuffIt 5 list/detect but read as `Unsupported` pending StuffIt codecs in `compcol`. Creation unsupported |
| 7z         | ✅    | —     | —              | 7-Zip read-only: parses the container (incl. LZMA-packed headers + solid folders sliced per substream); single-coder **Copy / LZMA / BZip2 / Deflate** folders decode (cross-checked with `7z`). **LZMA2** (the default), BCJ filters, PPMd, encryption and multi-coder pipelines list but read as `Unsupported` pending raw-LZMA2 + branch-filter codecs in `compcol`. Creation unsupported |

`🚧` marks writers / mutation paths with known gaps (see Limitations).
All writable filesystems — ext2/3/4, FAT12/16/32, exFAT, XFS, HFS+, NTFS,
APFS, F2FS, littlefs, SquashFS, ISO 9660, GRF — implement a single
`Filesystem` trait, so the CLI (`build`, `repack`, `add`, `rm`) and
the TOML `[filesystem] type = "…"` spec dispatch through one
codepath; pick a target FS by setting `--fs-type` on `repack` or
`type = "hfsplus"` (etc.) in the TOML spec. "In-place edits"
means an already-flushed image can be re-opened for `add` / `rm` /
`open_file_rw` — for filesystems with a journal, that path commits
through a real transaction so a crash mid-write leaves an image the
host's `fsck` can replay.

`qcow2`, `LUKS` and `dmg` are **not** in the table above: they aren't
filesystems but *disk-image containers*. They live one layer down, as
`BlockDevice` backends (see the architecture diagram and "Partitions,
block devices, qcow2, LUKS"), presenting a flat byte-addressable device that
any of the filesystems above is then laid down *inside* — fstool reads
and writes through them transparently. qcow2 is read/write (v2 + v3,
allocate-on-write), including **compressed** clusters — reads zlib and zstd
transparently (writing to a compressed cluster copies it out to a plain one)
— plus **backing files** and **encryption**; LUKS1 / LUKS2 volumes are
read/write and can be created; dmg is read-only (UDIF v4 mish chunks:
zero / raw / zlib / ADC / bzip2 / LZFSE / LZMA, plus encrypted v2
`encrcdsa`).

The reader for each FS streams: file contents are never fully resident in
memory regardless of size. The writers do the same, two-pass: scan to size
the geometry, then stream bytes from each source file into the image.

NTFS metadata that has no POSIX analogue (DOS attributes, ADS, security
descriptors, NT-FILETIME timestamps, short names, reparse data) round-trips
through xattrs under `user.ntfs.*` and `system.ntfs_security`.

## CLI commands

| Command       | What it does                                                            |
|---------------|-------------------------------------------------------------------------|
| `create`      | Build a bare image of any supported FS (`-t ext4` / `fat12` / `fat16` / `fat32` / `xfs` / `hfs+` / `ntfs` / `f2fs` / `littlefs` / `squashfs` / `iso` / `apfs` / `exfat` / `grf` / `zip` / `cpio` / `ar`) from a host directory tree. FS-specific knobs go through `-O key=val,key=val`. |
| `build`       | Build from a TOML spec — bare FS or a partitioned disk image.           |
| `info`        | Print partition table (whole-disk) or FS summary + root listing.        |
| `ls`          | List a directory inside an image; `-R` walks subdirectories recursively. |
| `cat`         | Stream a file's bytes out of an image to stdout. `--rsrc` streams the resource fork (HFS / HFS+). |
| `resources`   | Inventory an HFS / HFS+ file's resource fork (ResEdit-style: `vers`/`ICN#`/`DITL`/… with decoded summaries); `--extract TYPE:ID` dumps one resource. |
| `add`         | Copy a host file / tree into an existing image (any mutable FS).        |
| `rm`          | Unlink a file, symlink, device, or empty directory.                     |
| `shell`       | SFTP-style REPL — `ls cd pwd cat put get rm mkdir info` (`get` copies a file/dir out of the image to the host — the inverse of `put`), plus `find` (name/type/mtime filters, `-sort`/`-limit` for e.g. the N newest files) and `grep` (`-i`/`-n`/`-r`/`-v`/`-l`/`-c`; binary matches print as `hexdump -C`). Ctrl-C cancels a running `find`/`grep` without leaving the shell. `--with-cache` preloads all inodes into RAM so `find`/`ls` are instant; `--ro` browses read-only (incl. tar/ISO/SquashFS). On a TTY it has line editing + ↑/↓ command history (rustyline). |
| `convert`     | Byte-level raw ↔ qcow2 conversion with optional grow.                   |
| `repack`      | Walk one or more source FSes, merge bottom→top with whiteouts, rebuild into a fresh image. |
| `dd`          | Resilient raw block copy (file/device → file/device), `ddrescue`-style: reads in 1 MiB blocks that halve on error down to the source sector and skip unreadable spots. Threaded reader/writer pipeline with a live progress bar (%, ETA, separate read/write speed, buffer occupancy, current block, bytes skipped). Ctrl-C cancels cleanly. |

All commands accept partition-aware `disk.img:N` targets (1-indexed) — see
"Partitions, block devices, qcow2, LUKS" below.

Encrypted images — a LUKS volume, or a qcow2 with either `crypt_method` —
open with `--password` / `--password-file` on any command; commands that
*create* an image take `--encrypt` to make an encrypted one, and a qcow2
destination takes `--backing` to make it a thin overlay. See "Encryption"
and "Backing files" below.

All inspection / modification commands accept a `disk.img:N` (1-indexed)
target to walk into a partition of a GPT, MBR, or Apple Partition Map disk
image. `fstool info disk.img` without the suffix prints the partition table
itself.

### Path style (`--path-style`)

Classic Mac filesystems separate path components with `:`, so `/` is a legal
*filename* character (a real directory can be named `A/ROSE Includes`). The
global `--path-style` flag picks how paths are spelled:

- **`unix`** (default) — `/` separates everywhere; a literal `/` inside an
  HFS/HFS+ name is shown as `:` (the convention macOS itself uses). So
  `fstool ls disk.toast:2 …` lists `A:ROSE Includes`, and **repack to a tar/zip
  renders the name the same way** (`A:ROSE Includes`) — a literal `/` can't go
  in an archive member name without being read as a directory separator.
- **`native`** — the filesystem's own separator (`:` for HFS/HFS+, `\` for
  FAT/exFAT/NTFS, `/` elsewhere); real filenames are preserved. Navigate with
  the native separator, e.g.
  `fstool ls --path-style native disk.toast:2 ':Apple Software Library:…:A/ROSE Includes'`.

`native` only changes how the CLI and shell *display and accept* paths; on-disk
formats (and the canonical names used by `repack`/`add`) are unaffected.

### FS-specific options (`-O`)

Most filesystems expose tunables (block size, label, compression codec,
volume name, journaling on/off, etc.) through a generic `-O
key=value,key=value` flag that is repeatable, modelled on `mke2fs -O`:

```sh
# 4 KiB blocks + custom label on ext4
fstool create -t ext4 ./rootfs -o out.img -O block_size=4096,volume_label=ROOT

# Pick a SquashFS codec and tighten the block size
fstool create -t squashfs ./rootfs -o out.sqsh \
       -O compression=zstd,block_size=128KiB

# Force a v0x103 GRF with deflate level 9
fstool create -t grf ./rootfs -o out.grf -O version=0x103,compression_level=9

# littlefs sized to a flash part: 64 KiB erase blocks, 256-byte pages
fstool create -t littlefs ./rootfs -o out.img -O block_size=65536,prog_size=256
```

Each backend's `apply_options` validates keys; unknown keys are rejected
with a clear error citing the FS type. The same options are available
through the TOML spec — see "[filesystem.options]" below.

## Partitions, block devices, qcow2, LUKS

- **Partition tables** — MBR (4 primaries) and GPT (128-entry, CRC32 on
  header + entry array, primary + backup, protective MBR). Cross-checked
  against `sgdisk -v` and `fdisk -l`. **Apple Partition Map** (the classic
  Mac / `.toast` scheme) is read-only: `info` lists the `Apple_HFS` /
  `Apple_Free` / `Apple_partition_map` entries and `disk.toast:N` slices one.
- **Block devices** — on Unix, fstool can format and mutate real block
  devices (`/dev/sdX`, `/dev/nvme0n1`, loop devices). Capacity is queried via
  the kernel ioctl (`BLKGETSIZE64` on Linux, `DKIOCGETBLOCK*` on macOS) and
  open uses `O_EXCL` so the kernel refuses if any partition is mounted.
  Build commands require `--force` when the output is a block device.
- **qcow2** — `Qcow2Backend` reads QEMU v2 / v3 images and writes fresh v3
  ones with allocate-on-write. **Compressed clusters** are read transparently
  (zlib/deflate and zstd, decoded with a 4 KiB window to match qemu and bound
  RAM); a write to a compressed cluster copies it out to a plain cluster. To
  *produce* a compressed image, pass `--compress` to `create` / `build` /
  `repack` / `convert` (e.g. `--compress`, `--compress=9`, `--compress=zstd`,
  `--compress=zstd:9`); the result passes `qemu-img check`. Path-based
  factories (`block::open_image`, `block::create_image`) auto-dispatch by qcow2
  magic or file extension, so `fstool create -t ext4 src -o out.qcow2` Just
  Works.
- **LUKS** — `LuksBackend` unlocks a LUKS1 or LUKS2 volume with a passphrase
  and presents the decrypted payload as an ordinary device, so any filesystem
  above can live inside one. Read/write in place, and `luks::format` (or
  `fstool create --encrypt`) writes a fresh volume that `cryptsetup` opens.
  See "Encryption".

### Backing files

A qcow2 image may name a **backing file**: a base image supplying every
cluster the overlay has not allocated. `fstool` reads an overlay `qemu-img
create -b` produced, and creates its own:

```sh
# A thin ext2 overlay over an existing base; the overlay holds only its deltas.
fstool create -t ext2 --size 32M -o overlay.qcow2 \
       --backing base.qcow2 --backing-format qcow2
```

A relative `--backing` path is resolved against the *overlay's* directory
when the overlay is opened, so the pair stays movable together. Recording
`--backing-format` is what stops a raw base that happens to start with
qcow2 magic from being read as qcow2; without it the format is probed.
Writes copy the whole cluster up from the base first — a qcow2 cluster
shadows the base all-or-nothing — and zeroing a range over a base sets the
v3 ZERO flag rather than leaving the base showing through. Chains nest
(`MAX_BACKING_DEPTH` = 32) and a cycle is refused rather than followed.
Cross-checked against `qemu-img check` and `qemu-io` in both directions.

### Encryption

Three encrypted containers are supported, all served by
[`purecrypto`](https://github.com/KarpelesLab/purecrypto) — pure Rust, no
foreign code:

| Container | Read | Write | Create |
|-----------|------|-------|--------|
| **LUKS1 / LUKS2** | ✅ | ✅ | ✅ |
| **qcow2 `crypt_method = 2`** (embedded LUKS) | ✅ | ✅ | ✅ |
| **qcow2 `crypt_method = 1`** (legacy AES) | ✅ | ✅ | ❌ by design |
| **DMG `encrcdsa` v2** | ✅ | — | — |

```sh
# Put ext4 inside a fresh LUKS2 volume that `cryptsetup open` will unlock.
fstool create -t ext4 --size 1G -o secret.img tree/ --encrypt --password-file pw

# …or inside an encrypted qcow2 (a LUKS header embedded in the image, as
# `qemu-img create -o encrypt.format=luks` produces).
fstool create -t ext4 --size 1G -o secret.qcow2 tree/ --encrypt --password-file pw

# Every read/inspect/mutate command takes the same passphrase.
fstool ls   secret.img / --password-file pw
fstool info secret.img   --password-file pw
fstool add  secret.img ./new-file /new-file --password-file pw
```

Ciphers follow dm-crypt's `cipher-mode-ivgen` spelling: `aes`, `camellia`,
`aria` and `sm4` in `xts` / `cbc` / `ctr` / `ecb`, with the `plain`,
`plain64`, `plain64be`, `benbi`, `null` and `essiv:<hash>` IV generators.
`serpent` and `twofish` are recognised only well enough to refuse cleanly.
Keyslots derive through Argon2id / Argon2i (LUKS2) or PBKDF2 (either);
`--encrypt-kdf-iterations` and `--encrypt-kdf-memory` tune the cost, which
is the whole thing standing between a passphrase and a wordlist.

Two limits worth stating plainly. None of these modes **authenticate** —
a tampered sector decrypts to garbage rather than failing, exactly as
under dm-crypt — and LUKS `--integrity` volumes, which add a
`dm-integrity` layer, are refused rather than misread. And an encrypted
image opened without a passphrase is an error, not a device full of
ciphertext that a filesystem probe would misreport.

Cross-validated against `cryptsetup` (it recovers the same master key from
volumes each side wrote) and `qemu-io` / `qemu-img` (plaintext written by
one implementation reads back through the other).

## TOML spec

Declarative image descriptions — either a bare filesystem (`[filesystem]`)
or a partitioned disk (`[image]` + `[[partitions]]`):

```toml
[image]
size = "64MiB"
partition_table = "gpt"

[[partitions]]
name = "EFI"
type = "esp"
size = "16MiB"

[[partitions]]
name = "root"
type = "linux"
size = "remaining"

[partitions.filesystem]
type = "ext4"
source = "./rootfs"
```

```sh
fstool build disk.toml -o disk.img
sgdisk -v disk.img             # "No problems found."
```

### `source` — what to populate the FS with

`source` accepts three shapes, auto-detected by what the string points at:

```toml
[partitions.filesystem]
type = "ext4"
source = "./rootfs"            # a host directory — walk it recursively
```

```toml
[partitions.filesystem]
type = "ext4"
source = "./rootfs.tar.gz"     # a tar archive — repack entries into the FS
```

```toml
[partitions.filesystem]
type = "ext4"
source = "./old-disk.img:2"    # an existing image, optional :N partition
                               # — walks the source FS, copies every
                               # entry into the new partition
```

Recognised tar extensions: `.tar`, `.tar.gz`, `.tgz`, `.tar.xz`, `.txz`,
`.tar.zst`, `.tar.lz4`, `.tar.lzma`, `.tar.lzo` (codecs gated on the
matching Cargo feature). For images, the `:N` suffix selects partition
*N* (1-indexed); without it, the source is opened as a bare filesystem.
The source FS may be any readable type — `ext{2,3,4}`, FAT12/16/32, exFAT,
XFS, HFS+, APFS, NTFS, F2FS, littlefs, SquashFS, ISO 9660, tar, or GRF — and the
destination is sized automatically to fit unless `size` is set
explicitly.

### `[filesystem.options]` — FS-specific tunables

The same `-O key=val` knobs the CLI exposes are available in TOML
through a free-form `[filesystem.options]` table:

```toml
[filesystem]
type = "squashfs"
source = "./rootfs"

[filesystem.options]
compression = "zstd"
block_size  = 131072

[partitions.filesystem]
type = "ext4"
source = "./rootfs"

[partitions.filesystem.options]
block_size   = 4096
volume_label = "ROOT"
```

Recognised keys are documented next to each backend's
`FormatOpts::apply_options`; unknown keys are rejected at spec parse
time with a clear error citing the FS type. The existing flat fields
(`block_size`, `volume_label`, `mtime`, …) continue to work for
backward compatibility.

## Architecture

```
              ┌────────────────────────────────────────────┐
              │           CLI (clap) — bin/fstool          │
              └────────────────────────────────────────────┘
                                  │
              ┌────────────────────────────────────────────┐
              │  Spec layer (TOML → ImageSpec / FsSpec)    │
              └────────────────────────────────────────────┘
                                  │
              ┌────────────────────────────────────────────┐
              │  Filesystem trait → ext, fat, xfs, ntfs, … │
              └────────────────────────────────────────────┘
                                  │
              ┌────────────────────────────────────────────┐
              │  PartitionTable trait → Mbr, Gpt           │
              └────────────────────────────────────────────┘
                                  │
              ┌────────────────────────────────────────────┐
              │  BlockDevice trait → File, Mem, Sliced,    │
              │                       Qcow2, Dmg           │
              └────────────────────────────────────────────┘
```

Each layer is substitutable. A filesystem implementation talks only to a
`BlockDevice`; it doesn't know or care whether the device is a real file,
an in-memory buffer in a test, a slice carved out of a larger disk by a
partition table, or a qcow2-backed sparse container. DMG (`.dmg`) is
treated the same way: open the image, walk the mish table for the
chunk layout, and the rest of the stack reads through it as if it were
a flat block device — including the encrypted (`encrcdsa` v2) variant
when an unlock password is supplied.

## ext-specific niceties

- `BuildPlan` auto-sizes a filesystem to fit a source tree exactly
  (genext2fs-style "size to fit").
- `Ext::populate_rootdevs` drops a `Minimal` or `Standard` `/dev/*` tree
  (console, null, zero, ptmx, tty, fuse, random, urandom — plus tty0..15,
  ttyS0..3, kmsg, mem, port, hda..hdd, sda..sdd + partitions for
  `Standard`), so a non-root user can build a Linux root FS without
  `CAP_MKNOD`.
- xattrs round-trip through repack: both inline (extended-inode-body) and
  external `file_acl`-block sources are read; the destination writes to an
  external block with a correctly-computed CRC32C when `metadata_csum` is on.
  `debugfs ea_get` confirms identical values after repack.

## Cross-FS repack

`fstool repack` walks the source filesystem and rebuilds the tree into a
fresh image. With `--fs-type` it changes filesystem on the fly; `--shrink`
auto-sizes the output to the minimum that fits the content.

The pipeline is **one generic walker feeding one of two sinks** — a
streaming-tar sink (tar / `.tar.<codec>`) or a block-device `Filesystem`
sink — with no per-`(source,dest)`-type special cases. So **any readable
source repacks into any writable destination** through a single path
(`fstool repack app.zip out.tar`, `fstool repack disk.xfs out.iso`, …).
The walker reads each entry's metadata through the source's trait
`getattr` / `list_xattrs` / `read_symlink`, so mode, uid/gid, mtime,
symlinks, device numbers, xattrs, and hard links round-trip wherever both
ends can represent them. File bodies stream straight from source to
destination (`create_file_streaming`, no per-file tempfile). Hard links
are de-duplicated when the destination supports them (ext) and
materialised as copies otherwise (tar, FAT, …); a destination that can't
hold a symlink/device/xattr (FAT) drops it with a warning.

Every reader surfaces the metadata its format actually stores:
ext, tar, the archive formats, F2FS, XFS, SquashFS, APFS, and HFS+ carry
full POSIX mode/uid/gid + timestamps (HFS+ converts its 1904 epoch);
ISO 9660 does too when Rock Ridge is present (plain/Joliet have none);
littlefs stores none at all — no mode, owner, timestamps, symlinks or
device nodes — so it reports synthesised modes on read and refuses
symlink / device creation on write, and its user attributes ride through
repack as `user.littlefs.<type>` xattrs;
NTFS — which has no POSIX ownership — surfaces real timestamps + a mode
synthesised from its DOS attributes, and carries its native metadata
(DOS attrs, ADS, security descriptor, reparse data, …) through repack as
`user.ntfs.*` / `system.ntfs_security` xattrs.

`fstool repack` writes any destination implementing the `Filesystem`
trait — `ext2/3/4`, FAT12/16/32, exFAT, tar, XFS, HFS+, APFS, NTFS, F2FS,
littlefs, SquashFS, ISO 9660, GRF. `add` / `rm` go through the same trait,
which means they work on any FS whose writer can re-open an existing
image; today that's all of the mutable backends — ext, FAT12/16/32, exFAT,
XFS, HFS+, NTFS, APFS, littlefs, and GRF (F2FS is build-once: a re-opened
image is read-only). SquashFS, ISO 9660, and tar
are repack-only (their `MutationCapability` is `Immutable` or
`Streaming`, so `add` / `rm` fail fast with an actionable error and
the user is steered to `repack`).

## Layered merge with whiteouts

`repack` takes one or more source positional arguments followed by the
destination. With one source it behaves as before; with two or more
it merges the sources bottom→top before writing — later layers
override files of the same path, and tombstones from the upper
layer remove paths from the lower one. Two tombstone conventions are
auto-detected:

| Convention | Marker | Effect |
|------------|--------|--------|
| tar-OCI    | `.wh.<name>` in directory D | delete `D/<name>` |
| tar-OCI    | `.wh..wh..opq` in directory D | drop all lower-layer children of D before this layer's own land |
| OverlayFS  | character device with major=0, minor=0 | delete this path |
| OverlayFS  | xattr `trusted.overlay.opaque = "y"` on a dir | opaque-dir semantics on that dir |

The tombstones themselves never appear in the output. Sources may be
host directories, tar archives (compressed or plain), or filesystem
images — any mix works.

```sh
# OCI-style: rebuild a stack of layers into a flat tar
fstool repack base.tar layer1.tar layer2.tar flat.tar

# Patch an ISO with a tar of replacement files
fstool repack disc.iso patch.tar updated.iso --fs-type iso

# Shell globs work — last positional is the destination
fstool repack layer*.tar merged.tar
```

Internally the merge folds all layers into a single uncompressed tar
held in a tempfile, then drives the existing single-source repack
pipeline; the destination FS doesn't know it came from multiple
sources.

## ISO 9660

ISO 9660 reads cover the bare ECMA-119 layout plus three of the four
common extensions:

- **Joliet** (Microsoft) — UCS-2 BE long names via the supplementary
  volume descriptor.
- **Rock Ridge** (IEEE P1282) — POSIX mode + uid + gid via `PX`, long
  names via `NM`, symlinks via `SL`, timestamps via `TF`. Continuation
  areas (`CE`) are followed across sector boundaries.
- **El Torito** — boot catalog: validation entry, default entry, and
  section headers (`0x90` / `0x91`); the parsed catalog is surfaced
  in `fstool info`.

The writer is repack-only — ISO is sequential and a single `flush()`
writes the whole image. It emits a PVD plus optional Joliet SVD,
both L-type and M-type path tables, dual directory record trees (one
for PVD, one for Joliet), and Rock Ridge System Use Areas (`NM` /
`PX` / `SL`) attached to the PVD records. The output round-trips
through `isoinfo -lR` and back through fstool's own reader.

```sh
# Build an ISO from a host directory
fstool repack ./rootfs disc.iso --fs-type iso

# Walk an existing ISO
fstool ls   disc.iso /
fstool cat  disc.iso /README.TXT

# Round-trip ISO → tar → ISO
fstool repack disc.iso plain.tar
fstool repack plain.tar disc2.iso --fs-type iso
```

## Archive formats

Archives are treated as filesystems through the same `Filesystem` trait as
tar and GRF, so `info` / `ls` / `cat` / `repack` work on them uniformly. They
share a common core (`src/fs/archive/`): each format supplies a *scanner* that
indexes the archive into an in-memory tree, and — where writable — a *builder*;
the core provides the generic read path and decodes each entry's byte range
through the existing compression codecs.

```sh
fstool create -t zip ./rootfs -o out.zip          # build a zip from a dir
fstool create -t zip ./rootfs -o out.zip -O compression=stored
fstool ls   app.zip /                             # walk any zip/cpio/ar
fstool cat  app.zip /etc/config
fstool repack app.zip out.cpio --fs-type cpio     # convert between archives
```

| Format | Read | Write | Notes |
|--------|------|-------|-------|
| zip    | ✅    | ✅     | ZIP64, Stored + Deflate, Unix mode + symlinks; reads archives from any tool; filenames decoded as UTF-8 (flagged) else auto-detected (Shift-JIS / EUC-JP / Latin-9). On write the UTF-8 flag is set only for non-ASCII names. |
| cpio   | ✅    | ✅     | newc / newc-crc / odc read; newc write. |
| ar     | ✅    | ✅     | GNU + BSD long names on read, GNU on write. Flat — a nested source tree is rejected with a pointer to tar/zip/cpio. |

The writers are repack-only (`MutationCapability::Streaming`, like tar): an
existing archive can't be edited in place — `add` / `rm` steer you to
`repack`, which rebuilds. `cab` (Store/MSZIP/LZX/Quantum), `lzx` (Amiga
LZX), and `rar` (RAR5 Store/compressed, incl. **solid** groups) are read-only
readers via `compcol`, behind the `cab` / `amiga-lzx` / `rar` features. A
solid RAR group is decoded as one continuous stream; a sequential walk such
as `repack` decompresses it exactly once (a backward/random read of an
earlier member re-decodes from the group start, bounded memory). `lha`
(LHA/LZH, behind the `lha` feature) walks level-0/1/2 headers and reads
`-lh0-` store members; its LZSS+Huffman methods list but read as
`Unsupported` pending an `lha` codec in `compcol`. `arc` (SEA ARC, behind the
`arc` feature) walks the flat header chain and reads stored members; its
compressed methods list but read as `Unsupported` pending ARC codecs in
`compcol`. `sit` (StuffIt, behind the `sit` feature) parses the classic
`SIT!` container and reads stored members; its compressed methods and the
whole StuffIt 5 format list/detect but read as `Unsupported` pending StuffIt
codecs in `compcol`. `7z` (behind the `sevenz` feature) parses the full
container (LZMA-packed headers, solid folders sliced per substream) and reads
single-coder Copy / LZMA / BZip2 / Deflate folders; LZMA2 (the default), BCJ
filters, PPMd, encryption and multi-coder pipelines list but read as
`Unsupported` pending raw-LZMA2 + branch-filter codecs in `compcol`. Every
archive format now has a reader — there are no detection-only scaffolds left.
(`rar` and `sit` are read-only-at-best — their creation is proprietary; RAR4,
encrypted, stored-in-solid, and filtered-but-unsupported RAR5 streams stay
`Unsupported`.)

zip's Deflate support rides the existing `gzip` Cargo feature (raw DEFLATE via
`compcol`); a build without it falls back to Stored. `cpio` and `ar` need no
codec. Archive-to-`ext`/`fat`/`tar` repack uses the specialised FS-to-FS
copiers and isn't wired yet (same limitation as XFS/HFS+ sources) — convert
between archives, or to `iso`/`grf`, via the generic trait path.

## Using fstool as a library

The crate is a library first and a command second. The binary's
dependencies — `clap`, and `rustyline` for the shell's line editing — sit
behind the `cli` and `readline` features, and `[[bin]] required-features`
keeps the binary itself out of a library build. Depend on it like this:

```toml
[dependencies]
fstool = { version = "0.4", default-features = false,
           features = ["codecs", "containers"] }
```

`codecs` is every compression codec, `containers` every encrypted
container (LUKS, qcow2 encryption, encrypted DMG) — so that line keeps
each supported format while dropping the CLI and its ~26 transitive
crates. Take neither, or hand-pick individual features from the tables
below, to trim further.

The default feature set adds `cli` + `readline` on top, so `cargo install
fstool` and `cargo build` still produce a working command with no extra
flags. CI asserts the library-only resolve contains neither `clap` nor
`rustyline`.

## Compression

`fstool` ships with six compression codecs enabled by default. Each has
its own Cargo feature flag so you can trim the binary down:

| Codec | Feature | Used for |
|-------|---------|----------|
| gzip  | `gzip`  | SquashFS, `.tar.gz` / `.tgz` |
| xz    | `xz`    | SquashFS, `.tar.xz` / `.txz` |
| lzma  | `lzma`  | SquashFS, `.tar.lzma` |
| lz4   | `lz4`   | SquashFS, `.tar.lz4` |
| zstd  | `zstd`  | SquashFS, `.tar.zst` |
| lzo   | `lzo`   | SquashFS, `.tar.lzo` |

Crypto is feature-gated the same way, all three served by `purecrypto`:

| Feature | What it enables |
|---------|-----------------|
| `luks` | LUKS1 / LUKS2 volumes: unlock, read/write, format |
| `qcow2-crypto` | qcow2 encryption, both `crypt_method` values (implies `luks`) |
| `dmg-encrypted` | Password-protected DMG (`encrcdsa` v2), read-only |

A build without them refuses encrypted containers rather than silently
handing back ciphertext.

Compressed tar input / output is detected by filename extension (or by
magic for inputs without a recognisable extension): `fstool ls
disk.tar.zst /` and `fstool repack ext.img out.tar.gz` Just Work.
Internally the codec is streamed through a temp file so the whole
archive is never resident in RAM.

To disable a codec at build time, e.g. to avoid the bundled C `zstd`
build on a constrained system:

```sh
cargo install fstool --no-default-features --features gzip,lz4,xz,lzma
```

## Limitations

Things explicitly out of scope today, in rough order of likely-to-change:

- **ext4 write path**: `flex_bg` on the write path (reader is fine).
- **littlefs metadata**: the format stores no modes, owners, timestamps,
  symlinks or device nodes, so `create_symlink` / `create_device` return
  `Unsupported` (a repack sink skips those entries) and modes are
  synthesised on read. A metadata pair that empties out mid-chain is left
  in place rather than merged back into its predecessor — it costs one
  spare pair until the directory is removed. Wear-levelling relocation
  (`block_cycles`) is not modelled: an image tool rewrites a pair in
  place, which is a decision for the device that mounts it.
- **APFS in-place edits**: `open_file_rw` rebuilds a fresh COW
  checkpoint over the entire file content, so it's whole-file
  granularity — partial-extent COW is not yet implemented, and
  `create_file` / `remove` over the rw path piggyback on the same
  checkpoint. Multiple back-to-back commits are bounded by the
  `xp_desc` ring (the reader doesn't rotate it yet).
- **APFS reader**: snapshots are read-only and single-leaf snap-meta only
  (multi-level snap trees return `Unsupported`). `UF_COMPRESSED`/decmpfs file
  contents read as empty (the data isn't decoded yet, though the HFS+ decmpfs
  decoder could be reused). Encryption, sealed-volume integrity (hash/integrity
  tree), Fusion tiering, and dstream-backed (`XATTR_DATA_STREAM`) xattrs are out
  of scope.
- **APFS / NTFS strict-checker pass**: the spaceman + `$Secure` /
  `$LogFile` structures are now populated, but `fsck_apfs` and
  `ntfs-3g` mount can still flag the images for finer points
  (free-queue B-trees, journal metadata layout). Read + write work
  end-to-end; the host-tool gate is the remaining polish.
- **NTFS reader**: compressed and encrypted `$DATA`, `$ATTRIBUTE_LIST`
  spill, and security-descriptor indirection through `$Secure`
  beyond what the resident path handles all return `Unsupported`.
- **XFS reader**: B-tree-format (`di_format=BTREE`) directories
  deeper than one level above the leaves return `Error::Unsupported`
  (shortform / block / leaf / node and single-level B-tree dirs are
  covered); writer assumes shortform / extent dirs. Node-form
  (multi-leaf dabtree) xattrs are read-only.
- **HFS+ decmpfs**: type 3 (zlib inline) + type 4 (zlib resource
  fork) work. LZVN (types 7/8) and LZFSE (types 11/12) return
  `Unsupported`.
- **DMG**: read-only — no DMG writer / `convert` path. Encrypted v1
  (`cdsaencr` legacy 3DES) chunks return `Unsupported`; v2 is
  covered.
- **Partial-file rewrites** on the trait surface — `open_file_rw`
  exists everywhere it's safe, but a typed "patch this byte range
  on a known-large file" API is not surfaced beyond `Read + Write +
  Seek` on the handle.

## Try it

```sh
cargo install fstool                          # or: cargo install --path .
mkdir -p /tmp/src/etc && echo hi > /tmp/src/greeting.txt
fstool create -t ext4 /tmp/src -o /tmp/out.img
fstool info /tmp/out.img
fstool ls   /tmp/out.img /
fstool cat  /tmp/out.img /greeting.txt
e2fsck -fn  /tmp/out.img                      # must report clean
```

Run the test suite:

```sh
cargo test                    # unit tests + external cross-checks if tools present
```

CI runs the full suite on Linux (with `apt`-installed `e2fsprogs`,
`dosfstools`, `mtools`, `gdisk`, `qemu-utils` for cross-validation) plus a
build + test pass on macOS (Homebrew `qemu`) and Windows.

## Licence

MIT. Copyright © 2026 Karpelès Lab Inc. See [LICENSE](LICENSE).
