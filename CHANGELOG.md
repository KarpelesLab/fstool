# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.33](https://github.com/KarpelesLab/fstool/compare/v0.4.32...v0.4.33) - 2026-09-15

### Added

- *(fs)* statfs without an allocator, on every driver and generically

### Added

- *(fs)* `Volume::statfs` on the allocator-free FAT, exFAT and littlefs
  drivers, and on the `fs::volume::Volume` trait (so on `AnyVolume` too):
  capacity in `statfs` shape — the allocation unit (cluster or erase block),
  how many there are and how many are free, and the longest name. It
  answers with the same `fs::StatFs` the hosted `Filesystem::statfs` does,
  which is now compiled in every configuration, not only with `alloc`, and
  gains `total_bytes` / `free_bytes` / `avail_bytes`. The counts agree with
  what `fsck.vfat` and `dump.exfat` work out from the volume, and with
  littlefs's own traversal through `littlefs-python`. The trait method is
  provided — derived from `total_bytes` / `free_bytes` in 512-byte units —
  so an implementation written against 0.4.32 still compiles.

### Changed

- *(fs)* `StatFs` derives `PartialEq` and `Eq`.

## [0.4.32](https://github.com/KarpelesLab/fstool/compare/v0.4.31...v0.4.32) - 2026-09-15

### Added

- *(fs)* one no-alloc interface, a generic mount, formatters and partition writers

### Added

- *(fat)* `Volume::format` / `format_at`: the allocator-free driver formats.
  FAT12, FAT16 or FAT32 and the cluster size are chosen from the volume's
  size the way `mkfs.fat` and Windows choose them (FAT32 from 512 MiB, with
  Microsoft's cluster table and the data region on a cluster boundary), or
  set through `FormatOpts`. Only metadata is written, a sector at a time
  through one sector of stack, boot sector last. `fsck.vfat` passes every
  flavour at 512- and 4096-byte sectors, fresh and after use, and inside an
  MBR partition; the hosted `Fat32` reads them.
- *(exfat)* `Volume::format` / `format_at`, likewise: Microsoft's default
  cluster sizes (or `VolumeFormatOpts::cluster_size`), both boot regions with
  their checksum, one FAT, the allocation bitmap, a label, and the
  specification's recommended up-case table — the same 5836 bytes
  `mkfs.exfat` writes, so non-ASCII names fold as they do on any other card.
  The boot regions are written last. `fsck.exfat`, which checks the boot and
  up-case checksums, passes volumes from 8 MiB to 4 GiB at both sector sizes
  and inside a GPT partition; the hosted `Exfat` reads them. (The hosted
  `Exfat::format` still writes an ASCII-only table.)
- *(device)* `device::mbr::write` / `set_entry`: write a partition table, or
  change one slot of the one there, through a `SectorDriver` and a sector of
  scratch — boot code kept, CHS fields filled, the layout validated (inside
  the medium, no overlaps) before anything is written. Type-byte constants
  (`FAT32_LBA`, `EXFAT`, `LINUX`, …) and `FIRST_LBA` come with it. `sfdisk`
  reads back what they write, including changes to tables it wrote.
- *(device)* `device::gpt::write` / `set_entry` / `erase`: lay a GPT down
  (protective MBR, both headers and arrays, CRCs computed a sector at a time),
  change one entry of an existing table — rewriting both copies, which
  repairs a damaged one — or remove a table. Backup copy first, primary
  last, so a torn write leaves one whole table. `Layout` says where usable
  sectors start and end and where the 1 MiB-aligned first partition goes;
  `Guid::random_v4` makes a well-formed GUID from the caller's random bytes.
  `sgdisk -v` passes the tables and `sgdisk -i` reads back every field; the
  `device_tables` fuzz target now runs `set_entry` over arbitrary media (it
  found an overflow on a header pointing its array off the medium, fixed).
- *(fs)* `fs::volume::format` and `FormatAs`: format any compiled-in
  filesystem through the generic layer — littlefs on a card through
  `SectorFlash` — and get an `AnyVolume` back. `FormatAs::sd_card` picks what
  the SD specification requires for a card's size: FAT up to 32 GiB, exFAT
  above.
- *(fs)* `fs::volume`: one interface over every allocator-free driver.
  `fs::fat::Volume`, `fs::exfat::Volume` and `fs::littlefs::Volume` all
  implement its `Volume`, `VolumeFile` and `VolumeDirIter` traits, so code
  written once — open, read, write, seek, truncate, list, create and remove
  — runs on any of them. Sizes are `u64` and names bytes (with `name_str`)
  whatever the driver stores; a listing never reports FAT's `.` and `..`;
  every driver error answers `kind()` with a shared `ErrorKind`, so generic
  code can tell `NotFound` from `Io` without knowing whose error it holds.
  The traits are generic rather than `dyn`, need no allocator, and cost
  nothing over calling the driver directly. The drivers' own APIs are
  unchanged.
- *(fs)* `fs::mount` / `fs::volume::probe`: find out what a card holds and
  mount it. The whole medium is tried, then each GPT or MBR partition in
  order, and at each start the compiled-in filesystems are recognised by
  their own signatures — exFAT boot sector, a FAT BPB that validates, a
  littlefs superblock log — never by a partition type. The result is an
  `AnyVolume`, which implements the same traits, and whose `AnyError` keeps
  the driver's error whole. `probe` answers without taking the card. Checked
  against volumes `mkfs.fat` (inside an `sgdisk` GPT), `mkfs.exfat` (whole
  card and MBR slot) and littlefs's C implementation (512-, 1024- and
  4096-byte blocks, after enough churn to compact the superblock) wrote: each
  is found, edited through the traits, and passed by its own tool afterwards.
  A new `volume_mount` fuzz target feeds `probe` and `mount_found` arbitrary
  media.
- *(device)* `device::SectorFlash`: a `SectorDriver` presented as a
  `FlashDriver`, one erase block per run of sectors — littlefs on an SD card
  or eMMC part, where never overwriting live metadata is exactly what a card
  pulled mid-write needs. `fs::mount` uses it to mount littlefs found on a
  card. Erase really writes `0xff`, as the flash contract promises the
  driver.

### Changed

- *(fat)* `DirEntry::name` returns `&'a str`, borrowed from the iterator
  rather than from the entry, like exFAT's and littlefs's already did. Code
  that compiled before still does.

## [0.4.31](https://github.com/KarpelesLab/fstool/compare/v0.4.30...v0.4.31) - 2026-09-13

### Added

- *(device)* [**breaking**] allocator-free exFAT and littlefs drivers on a shared storage layer

### Fixed

- *(test)* count the leak test's allocations per thread

### Added

- *(crc)* `crc::crc32_small` / `crc32_small_append`: the same CRC-32 as
  `crc32`, computed bit by bit with no lookup tables. The table-driven one
  folds eight bytes at a time through 8 KiB of tables, which is the right
  trade for a filesystem's worth of data and the wrong one for the 92 bytes of
  a GPT header — linking it into the Cortex-M example cost 8.3 KB of flash for
  that one check.
- *(device)* `device::gpt`: an allocation-free reader for the EFI GUID
  Partition Table, which is what anything above 2 TB uses, what every UEFI
  machine boots from, and what a card that has been through a PC often
  carries. It verifies the header's CRC-32 and falls back to the backup header
  at the end of the medium when the primary fails it — the reason the format
  keeps two — decodes entries one at a time through a sector of the caller's
  scratch, and needs neither an allocator nor 512-byte sectors (the hosted
  `part::Gpt` requires those; this reader takes the entry array's position
  from the header). Type GUIDs for the partitions a FAT-family volume lives
  in are named, and `Partition::name_from` reads a label into a caller's
  buffer.

  `fs::fat`'s and `fs::exfat`'s `mount_auto` / `probe` now consult it: a GPT
  is tried before the MBR, since a GPT medium carries a protective MBR whose
  one entry describes the table rather than a volume — which `device::mbr`
  now skips as well. Validated against tables `sgdisk` writes, against the
  crate's own `part::Gpt` writer, and by a `device_tables` fuzz target that
  feeds both readers arbitrary bytes (it found an overflow in the sector count
  of an entry naming the whole 64-bit range within minutes of being written).
- *(exfat)* an allocation-free exFAT driver, in `fs::exfat` beside the
  hosted one — the filesystem an SDXC card arrives formatted with, so the
  one an embedded card reader most needs. It needs no heap at all: the FAT
  and the allocation bitmap are read and written a sector at a time through
  a single-sector write-back cache, and the up-case table is consulted on
  the card rather than held in memory (its ASCII range, which covers almost
  every comparison, is read once at mount). It is the *same* `SectorDriver`
  trait `fs::fat`'s driver uses, so one implementation over an SD/eMMC
  driver mounts either filesystem — and `Volume::probe` says which a card
  holds without consuming it. Mounts whole cards or MBR partitions, reads,
  writes, appends, truncates, creates and removes files and directories,
  lists them, honours `NoFatChain` runs on read and converts one when it
  grows, and compares UTF-16 names case-insensitively through the volume's
  own table.

  Validated against exfatprogs both directions: volumes the driver
  populates pass `fsck.exfat`, and a volume `mkfs.exfat` created — standard
  compressed up-case table and all — is read, extended and still clean
  afterwards, including after the hosted half and the driver take turns
  writing to it. The `examples/embedded-cortex-m` heapless binary links it
  for a Cortex-M4F with no `#[global_allocator]` at all.
- *(exfat)* `Volume::upcase_cache_bytes`: with `alloc`, the up-case table is
  decoded into memory on first need instead of being walked on the card for
  every non-ASCII comparison. Pure optimisation — the same calls, the same
  answers, far fewer reads.

### Changed

- **breaking** *(device)* the traits a storage driver implements moved out of
  the filesystems and into `fstool::device`, which is where they belong: one
  of them serves two filesystems, and none of them knows or cares which
  filesystem is above it. `device::SectorDriver` (cards) is what `fs::fat`
  and `fs::exfat` are written against; `device::FlashDriver` (raw flash) is
  what `fs::littlefs` is. Those two traits are the whole contract a consumer
  implements, so nothing else shares the namespace: the partition table a
  driver *reports* is data, and lives in `device::mbr` as
  `mbr::Partition` + `mbr::parse`. The module allocates nothing and is
  compiled in every configuration.

  `fs::fat::SectorDriver` and `fs::fat::MbrPartition` shipped in 0.4.30 and
  still resolve. `MbrPartition` is a deprecated alias for
  `device::mbr::Partition`, so a build using it says so; `SectorDriver` is a
  re-export, and rustc ignores `#[deprecated]` on those, so that one carries
  the notice in its documentation only. Implementations of either trait need
  no change — only the import, and only if you want the canonical path.
  `block` re-exports both traits beside its own `SectorIo`, so a hosted
  reader still finds the whole storage layer in one place. The exFAT and
  littlefs drivers, which are new in this release, publish no mirrors at all.

  This also ends `fs::exfat` reaching into `fs::fat`'s private `volume::boot`
  module for MBR parsing, which is what made the sharing visible in the first
  place — there is now one MBR decoder in the crate's allocator-free layer
  instead of a copy behind a filesystem.
- *(features)* `exfat` no longer implies `alloc`. On its own it is now the
  allocation-free driver, so `default-features = false, features = ["exfat"]`
  builds for a target with no heap; with `alloc` (any `std` or default
  build) it additionally compiles the hosted `Exfat` exactly as before. It
  still implies `fat`, whose `SectorDriver` it shares. No hosted build
  changes.

### Fixed

- *(fat)* `Volume::unmount` leaked the in-memory allocation table — up to
  megabytes on a large card. Handing the device back means moving it out of
  a type that implements `Drop`, which only `ManuallyDrop` allows, and that
  suppresses the drop glue of *every* field rather than just the device's.
  The cache is now released explicitly, and an exhaustive field pattern next
  to it stops compiling if a future field that owns memory is added without
  a decision being made about it. `tests/driver_no_leak.rs` — a test binary
  with its own counting allocator — watches all three drivers for it.
- *(test)* the exFAT conformance tests took `fsck.exfat`'s exit status as
  the verdict, but with `-n` it answers "no" to every repair prompt and
  exits 0 even after printing `ERROR:` — so a volume it complained about
  passed. They now hold it to its report.

### Added

- *(littlefs)* an allocation-free littlefs driver, in `fs::littlefs`
  beside the hosted one. It needs no heap at all: one block of scratch RAM
  holds the metadata pair being worked on, a commit is programmed out
  through a staging buffer the size of one flash page, and block
  allocation traverses the filesystem into a fixed 256-block lookahead
  window, exactly as the C implementation does. `FlashDriver` is the trait
  you implement over your flash — read, program, erase, sync, mirroring
  littlefs's own `lfs_config` — and the driver mounts, formats, reads,
  writes, appends, truncates, creates and removes files and directories,
  lists them, and reads and writes littlefs user attributes. Metadata
  pairs are read by walking their tag log rather than replaying it into
  owned entries, so a log full of overrides and splices — what a stock
  littlefs writes constantly — is read without materialising anything.

  Validated both directions against the reference C implementation through
  `littlefs-python`: images the driver writes mount there and agree block
  for block on which blocks are live, images it wrote read back
  identically, and a volume written by the driver, then by littlefs, then
  by the driver again stays consistent. The new
  `examples/embedded-cortex-m` binary links it for a Cortex-M4F with no
  `#[global_allocator]` at all — a compile-time proof CI runs on every
  push — in ~28 KB of flash, with a footprint that does not grow with the
  size of the flash.
- *(littlefs)* `Volume` keeps an exact in-use bitmap of the whole volume
  when `alloc` is on, so allocation stops re-traversing the filesystem
  every time its lookahead window runs dry.
  `Volume::alloc_cache_bytes` reports how much is held (always 0 without a
  heap). Pure optimisation: same calls, same answers, far fewer reads.

### Changed

- *(features)* `littlefs` no longer implies `alloc`. On its own it is now
  the allocation-free driver, so `default-features = false, features =
  ["littlefs"]` builds for a target with no heap; with `alloc` (any `std`
  or default build) it additionally compiles the hosted `LittleFs` exactly
  as before. No hosted build changes.

### Fixed

- *(littlefs)* mounting no longer trusts a fixed offset in block 0 for the
  superblock: the driver reads it through the metadata *pair*, so a volume
  whose live half of `{0, 1}` was scribbled over still mounts from the
  other half, which is the guarantee a pair exists to make.

## [0.4.30](https://github.com/KarpelesLab/fstool/compare/v0.4.29...v0.4.30) - 2026-09-12

### Fixed

- *(fat)* export the driver's error as `fs::fat::Error`
- *(build)* drop the cdylib crate type so a no_std build needs no panic handler

### Other

- record the fs::fat move as breaking, with the one-line migration
- v0.4.29 release commit from origin
- *(fat)* [**breaking**] one module, one API shape — `fs::fat` with or without a heap

### Fixed

- *(build)* the library declared a `cdylib` alongside its `rlib`, which
  made every build produce a linked artifact. In a `no_std` configuration
  that artifact demands a `#[global_allocator]` and a `#[panic_handler]`
  the library has no business providing, so
  `cargo build --no-default-features --features fat` failed for a reason
  unrelated to the code, and a firmware target only avoided it because
  cargo dropped the crate type with a warning on every build. The crate
  is an `rlib` now; the browser bundle asks for a `cdylib` on the command
  line (`cargo rustc --crate-type cdylib`).

### Changed

- **breaking** *(fat)* the allocation-free driver moved from
  `fstool::noalloc::fat` to `fstool::fs::fat`, where FAT already lived.
  Rename the import and nothing else changes:
  `use fstool::noalloc::fat::{SectorDriver, Volume}` becomes
  `use fstool::fs::fat::{SectorDriver, Volume}`. The `fstool::noalloc`
  module is gone.

  One module now holds the whole backend and `alloc` only ever adds to
  it: without a heap you get the driver, with one you additionally get
  the hosted `Fat32` (the `Filesystem` implementation) and an in-memory
  allocation table that makes the driver faster through the same API.
  Nothing about a call or a type depends on the feature.

### Added

- *(fat)* `Volume` keeps the allocation table in memory when `alloc` is
  on, filling lazily a sector at a time and mirroring its own writes, so
  walking a cluster chain stops re-reading the table.
  `Volume::fat_cache_bytes` reports how much is held (always 0 without a
  heap). Pure optimisation: same calls, same answers, fewer transfers.

## [0.4.29](https://github.com/KarpelesLab/fstool/compare/v0.4.28...v0.4.29) - 2026-09-12

### Added

- *(fat)* FAT12/16/32 with no allocator at all

### Fixed

- *(fat)* six bugs an independent review found in the no-alloc driver
- *(fat)* bound every cluster-chain walk in the no-alloc driver, and fuzz it
- *(exfat)* validate the name inside make_file_entry_set
- *(exfat)* refuse a read-write handle on a volume with no allocation bitmap
- *(exfat)* bound ClusterCount by the spec maximum
- *(fat)* widen the backup-boot-sector bound check so 0xFFFF cannot wrap
- *(littlefs)* bound the rw handle's pending write buffer
- *(exfat)* keep a grown directory's DataLength current in its parent
- *(exfat)* size files by DataLength and read zeros past ValidDataLength
- *(exfat)* reject names longer than 255 UTF-16 units
- *(fat)* ignore the reserved cluster-high half on FAT12/16; cap names at 255 units
- *(fat)* require every path-prefix component to be a directory in resolve_entry
- *(exfat)* patch entry sets via the flat directory buffer; refuse duplicate names
- *(fat)* unique generated short names per directory; forget removed names
- *(fat)* reject files of 4 GiB or more instead of storing the size modulo 2^32
- *(exfat)* free the whole contiguous run when removing a NoFatChain file
- *(exfat)* compute the rw handle's cluster requirement in u64
- *(fat)* validate FSInfo / backup boot sector numbers before flush writes them
- *(fat)* reject a FAT too small to map every cluster, and index the table safely
- *(exfat)* size the allocation bitmap in clusters at format time
- *(exfat)* allocate from the allocation bitmap, not the FAT

### Other

- fix the two tests CI caught and local runs could not
- apfs/hfs/hfs+/affs fixes (journal byte order, hashed drec keys, HFSX collation, bitmap extents)
- name alloc in the default feature list
- *(features)* [**breaking**] make no-alloc the floor and `alloc` additive
- ntfs + f2fs fixes (USA stride, index VCNs, LZNT1, NAT layout, device nodes)
- ext + xfs fixes (inode bitmap, whole-inode checksum, uninit_bg, HTree seed; xfs rdev/attr forks/bmbt root)
- fat/exfat/littlefs fixes (bitmap-authoritative exFAT allocation, FAT geometry validation)
- *(littlefs)* move truncate above the test module
- *(fat)* skip the metadata rewrite on flush when no FAT entry changed

### Added

- *(fat)* an allocation-free FAT12/FAT16/FAT32 driver, in `fs::fat`
  beside the hosted one. Every buffer is a fixed array or comes from the
  caller and the allocation table is read a sector at a time from the
  device, so it runs with no heap at all; `alloc` adds the hosted
  `Filesystem` implementation and keeps the table in memory, making the
  same API faster without changing its shape. Reads and writes, long
  names, subdirectories and MBR partitions. The new
  `examples/embedded-cortex-m` binary links it for a Cortex-M4F with no
  `#[global_allocator]` at all — a compile-time proof CI runs on every
  push — in ~19 KB of flash and under 1 KiB of RAM per mounted volume.
- *(features)* `alloc`, a default feature that the `std` build and every
  backend needing a heap imply. It is additive: turning it off removes
  the layers that require one and leaves the allocation-free floor;
  turning it on never takes anything away.

### Changed

- *(features)* `fat` no longer implies `alloc`. On its own it is now the
  allocation-free driver, so `default-features = false, features = ["fat"]`
  builds for a target with no heap; with `alloc` (any `std` or default
  build) it additionally compiles the hosted `fs::fat` exactly as before.
  `exfat`, which shares the hosted driver's allocation-table code, now
  names `alloc` explicitly. No hosted build changes.

## [0.4.28](https://github.com/KarpelesLab/fstool/compare/v0.4.27...v0.4.28) - 2026-09-12

### Added

- per-format Cargo features and a no_std core for embedded targets

### Fixed

- *(repack)* rebase add_dir_tree under its destination, collapse duplicate stream entries
- *(cli)* refuse to convert/repack an image onto itself, gate device output on --force

### Other

- pass the example's linker script explicitly under the job-level RUSTFLAGS
- keep the no_std example's entry point under --gc-sections and fail on an empty image
- grf implies gzip — every GRF member is zlib-compressed
- *(block)* mount FAT inside an MBR partition on a SectorDevice

## [0.4.27](https://github.com/KarpelesLab/fstool/compare/v0.4.26...v0.4.27) - 2026-09-09

### Added

- *(ext4)* honour metadata_csum_seed when stamping checksums

### Fixed

- *(affs)* treat DOS\4/DOS\5 as international and maintain the directory cache

## [0.4.26](https://github.com/KarpelesLab/fstool/compare/v0.4.25...v0.4.26) - 2026-09-05

### Other

- parse the TOML spec with tomlproc instead of the toml crate
- gate serde, toml, log and libc behind capability features

### Changed

- *(deps)* the `spec` feature now parses TOML with `tomlproc`
  (KarpelesLab) instead of the `toml` crate. `tomlproc` is a
  self-contained TOML 1.0.0 implementation whose only dependency is the
  `serde` we already take, so six crates leave the tree — `toml`,
  `toml_datetime`, `toml_parser`, `toml_writer`, `serde_spanned` and
  `winnow` — for one. The default resolve goes 26 → 21 crates. The
  public `FilesystemSpec::options` field changes type from `toml::Table`
  to `tomlproc::Table`, as does `OptionMap::merge_toml`'s argument.

- *(deps)* four more capabilities are feature-gated, all on by default:
  `spec` (the TOML engine → `toml` + `serde`), `json` (`Serialize`, the
  `--json` output, the wasm bridge, and LUKS2 → `serde` + `serde_json`),
  `log` (the facade → `log`), and `unix-host` (block-device ioctls,
  `O_EXCL`, terminal width, Ctrl-C → `libc`). Defaults are unchanged, so
  nothing moves for existing users; `--features codecs` alone is now a
  7-crate build whose only third-party dependency is `uuid`. CI checks
  that floor builds, lints and passes its tests.

## [0.4.25](https://github.com/KarpelesLab/fstool/compare/v0.4.24...v0.4.25) - 2026-09-04

### Fixed

- *(grf)* refuse a filename CP949 cannot hold, instead of mangling it

### Other

- *(deps)* drop thiserror, encoding_rs, crc32fast and crc32c
- *(apfs)* hash drec names through intl instead of caseless
- *(apfs)* pin the case-fold vectors that justify the caseless dep

## [0.4.24](https://github.com/KarpelesLab/fstool/compare/v0.4.23...v0.4.24) - 2026-09-01

### Other

- keep the CLI's dependencies out of library consumers

### Changed

- *(cargo)* the CLI's dependencies no longer reach library consumers. `clap`
  is optional behind a new `cli` feature, the binary carries
  `required-features = ["cli"]`, and `PathStyle`'s `ValueEnum` derive is
  `cfg_attr`-gated on the same flag. New `codecs` and `containers` umbrella
  features make the library-only line short —
  `default-features = false, features = ["codecs", "containers"]` keeps every
  format while dropping `clap` and `rustyline` (60 → 34 crates). Defaults are
  unchanged, so `cargo install fstool` still yields a working command; CI
  asserts the library-only resolve contains neither.

## [0.4.23](https://github.com/KarpelesLab/fstool/compare/v0.4.22...v0.4.23) - 2026-08-30

### Added

- *(cli)* open, create and inspect encrypted images and qcow2 overlays
- *(qcow2)* read and write encrypted images, and create LUKS ones
- *(qcow2)* follow backing files, and create overlays over them
- *(luks)* read, write and format LUKS1 and LUKS2 volumes

### Fixed

- *(block)* keep CreateOpts::default()'s 64 KiB cluster size
- *(luks)* bound header-controlled allocations, and use the spare copy
- *(qcow2)* keep zero_range sparse, and bound the fresh refcount block

### Other

- adopt as_chunks for the fixed-width decoders clippy now flags
- cover LUKS, qcow2 backing files and encryption
- *(base64)* graduate the DMG decoder into a shared crate module

### Added

- *(luks)* new `block::luks` backend for LUKS1 and LUKS2 volumes: unlock with
  a passphrase (or a master key), read and write the payload in place, and
  format a fresh volume. Ciphers follow dm-crypt's `cipher-mode-ivgen`
  spelling — `aes` / `camellia` / `aria` / `sm4` in `xts` / `cbc` / `ctr` /
  `ecb`, with the `plain`, `plain64`, `plain64be`, `benbi`, `null` and
  `essiv:<hash>` IV generators — and keyslots derive through Argon2id /
  Argon2i or PBKDF2. All of it on `purecrypto`, behind the `luks` feature.
  Volumes we cannot read faithfully (`--integrity`, unmet
  `config.requirements`, an interrupted online re-encryption) are refused
  rather than misread. Cross-validated against `cryptsetup` and `qemu-io`.
- *(qcow2)* backing files: an overlay reads through to its base for every
  cluster it has not allocated, writes copy the cluster up first, and
  `create_with_backing` produces overlays `qemu-img check` accepts. The v3
  ZERO flag is now honoured, so a zeroed range shadows the base instead of
  letting it show through. Chains nest, and a cycle is refused.
- *(qcow2)* encryption, both `crypt_method` values: LUKS (a header embedded
  in the image, which `create_encrypted` also writes) and the legacy AES
  scheme, which can be opened and rewritten but — as in qemu since 2.9 — not
  created. Behind the `qcow2-crypto` feature.
- *(cli)* `--password` / `--password-file` on every command, for LUKS volumes
  and encrypted qcow2 images; `--encrypt` (with `--encrypt-cipher`,
  `--encrypt-format`, `--encrypt-key-bytes`, `--encrypt-kdf-iterations`,
  `--encrypt-kdf-memory`) on the commands that create an image; `--backing`
  / `--backing-format` for a qcow2 overlay. `fstool info` now leads with what
  the container is — qcow2 version, cluster size, backing file, encryption
  method; or the LUKS header's own summary.

### Changed

- *(block)* `open_image` and friends now refuse an encrypted container
  instead of returning ciphertext a filesystem probe would misreport; the
  `*_with_password` variants open it. `CreateOpts` grew `encrypt` and
  `backing` fields (and is no longer `Copy`).
- *(base64)* the DMG plist decoder graduated to `crate::base64` and grew an
  `encode` counterpart, for LUKS2's JSON metadata.

## [0.4.22](https://github.com/KarpelesLab/fstool/compare/v0.4.21...v0.4.22) - 2026-08-17

### Added

- *(littlefs)* read, write and in-place edits for lfs2 images
- *(web)* create, edit and download images in the browser
- *(memedit)* in-memory authoring — blank filesystems, partitioned disks

### Fixed

- *(littlefs)* accept both path separators, fixing Windows
- *(littlefs)* split metadata pairs on entry size alone
- *(ext)* honour journal revoke records across transactions
- *(ext)* decode HTree directory roots and honour journal revoke blocks ([#32](https://github.com/KarpelesLab/fstool/pull/32))

### Other

- cover littlefs in the prose, and refresh the crate front page

### Added

- *(littlefs)* new backend for the embedded-flash filesystem (`lfs2`, disk
  versions 2.0 and 2.1): read, write, and in-place edits. Metadata pairs are
  replayed from their CRC-committed logs (tags, splices, tails, global-state
  deltas, lfs2.1 forward-CRCs) and written back as compactions; files live
  inline in metadata or in CTZ skip-lists, which are rebuilt only from the
  first changed block onwards so a partial write leaves earlier blocks
  untouched. Block allocation reconstructs the in-use map by traversing the
  volume, as littlefs itself does. Wired into `create -t littlefs`, the TOML
  spec (`type = "littlefs"`, with `block_size` / `block_count` / `prog_size` /
  `version` / `name_max` / `inline_max` options), `repack --fs-type littlefs`,
  `info`, `add`/`rm`, the in-memory authoring surface, and the browser build.
  littlefs user attributes surface as `user.littlefs.<type>` extended
  attributes; the format has no symlinks, device nodes or POSIX metadata, so
  those are refused rather than faked. Cross-validated in both directions
  against the reference C implementation via `littlefs-python`, including
  handing an image back and forth mid-edit.

- *(memedit)* new in-memory authoring surface: `Workspace` formats a blank
  filesystem or lays out a partitioned disk (MBR/GPT), takes files and
  directories, and hands back the image bytes at any point.
  `creatable_filesystems()` advertises 15 types with their real minimum sizes.
- *(wasm)* `Workspace` and `creatable_filesystems()` bindings, so the browser
  build can author images as well as read them.
- *(web)* "Create a new image" mode: pick a filesystem and size, or build a
  partitioned disk with a filesystem per partition, then add files, delete
  them, browse directories, and download the image — repeatedly, while
  continuing to edit. An uploaded image can also be switched into edit mode.

### Fixed

- *(ext)* journal recovery now honours revoke records across transactions.
  Replay was single-pass and scoped each revoke to the transaction that
  carried it, so a block revoked in transaction *N+1* was still replayed from
  transaction *N* — it had already been written by the time the revoke record
  was read. That is exactly the case revoke records exist to prevent (a
  metadata block freed and reused as file data), so stale metadata could land
  on live data. Recovery now runs the two passes JBD2 requires: a scan that
  collects committed transactions and builds a revoke table keyed by the
  highest revoking transaction id, then a replay that skips any block whose
  revoke id is at or after the transaction replaying it (the kernel's
  `jbd2_journal_test_revoke` rule, wrap-safe). An uncommitted tail
  transaction's revoke records are discarded along with its writes.
- *(ext)* `parse_descriptor_tags` walked the tag array in 8-byte steps
  regardless of the journal's real tag size, so a trailing slot too short for
  a 16-byte checksum-v3 tag failed the whole replay instead of ending the
  array; it also read into the 4-byte checksum tail that checksum-v2/v3
  descriptor blocks carry.

## [0.4.21](https://github.com/KarpelesLab/fstool/compare/v0.4.20...v0.4.21) - 2026-08-17

### Added

- *(fat)* read + write FAT12 and FAT16 alongside FAT32

### Fixed

- *(ext)* 60-byte symlinks inline, and used_dirs_count charged to group 0
- *(fat)* don't link private `DirLayout` from the public module docs

### Other

- *(fat)* cross-validate FAT12/16 against dosfstools and mtools; document
- *(deps)* bump compcol to 0.6.10

### Added

- *(fat)* read + write FAT12 and FAT16 alongside FAT32. One backend serves
  all three: `table::FatKind` owns the 12/16/32-bit entry width (including
  FAT12's 1.5-byte packing) and `DirLayout` reduces both directory shapes —
  a cluster chain and the FAT12/16 fixed root region — to a list of device
  extents. A volume's flavour is derived from its data-cluster count per the
  spec, so images that mislabel their `fs_type` string still open correctly,
  and `detect_fs` probes the BPB rather than looking for a magic string
  FAT12/16 don't have. Reachable as `create -t fat12|fat16`, as a `repack`
  destination, and as a TOML spec `type`; `-O root_entries=` sizes the fixed
  root, which cannot grow once formatted.

### Fixed

- *(ext)* a symlink target of exactly 60 bytes was stored inline in `i_block`,
  producing an inode `e2fsck` rejects ("Symlink … is invalid") and the kernel
  refuses to look up ("invalid fast symlink length 60"). ext carries no
  "is inline" flag — the reader infers it from size alone, and Linux tests
  `i_size < 60` — so the bound is now strict in both the writer and the size
  planner, which had the same off-by-one and would have under-reserved a block
  per such symlink. ([#33](https://github.com/KarpelesLab/fstool/issues/33))
- *(ext)* `bg_used_dirs_count` was charged to block group 0 for every
  directory, so any image whose inodes reached a second group failed `e2fsck`
  with "Directories count wrong for group #N". Each directory is now counted in
  its own group, which also removes the only way to overflow the `u16` — per
  group it is bounded by `inodes_per_group`.
  ([#34](https://github.com/KarpelesLab/fstool/issues/34))

### Changed

- *(fat)* `FatFormatOpts` gained `kind` and `root_entries` — struct literals
  need `..Default::default()`. `Fat32::geometry` now takes the flavour and a
  root size and returns a `Geometry`. `table::{EOC, EOC_MIN, ENTRY_MASK}` are
  replaced by width-aware `FatKind` methods. FAT32 geometry, error text and
  on-disk output are unchanged.
- *(deps)* bump `compcol` floor to 0.6.10.

## [0.4.20](https://github.com/KarpelesLab/fstool/compare/v0.4.19...v0.4.20) - 2026-07-12

### Fixed

- *(squashfs)* converge inode/dir metablock offsets (Alpine root truncation)

### Other

- *(repack)* generic walk_stream over ArchiveStream; deprecate walk_tar_stream

## [0.4.19](https://github.com/KarpelesLab/fstool/compare/v0.4.18...v0.4.19) - 2026-07-12

### Added

- *(web)* in-browser WebAssembly UI + in-memory inspect/convert API

### Fixed

- *(hfs+)* restore create_file_streaming override clobbered in merge
- *(web)* keep [hidden] elements hidden over author display rules

### Other

- de-link private intra-doc references (rustdoc -D warnings)
- *(f2fs)* use map values()/keys() to satisfy clippy for_kv_map
- *(fs)* sequential archives hold no index — forward-scan on read
- *(fs)* honest per-file read seekability — no RAM-faked Seek
- *(fs)* finish write-path streaming; add AccessMode capability
- *(fs)* stream file bodies on write; drop tempfile dependency
- *(web)* rebuild UI in Vue 3 + Vite; fold wasm bindings into fstool crate
- link the live web demo in the README
- lower MSRV to 1.88 (purecrypto 0.6.14)

## [0.4.18](https://github.com/KarpelesLab/fstool/compare/v0.4.17...v0.4.18) - 2026-06-16

### Added

- *(hfs+)* set_attrs for cross-filesystem chmod/chown
- *(xfs)* implement set_attrs for cross-filesystem chmod/chown/utimes
- *(exfat)* set_attrs for cross-fs chmod via the READ-ONLY bit
- *(fat)* implement set_attrs so cross-fs chmod works on FAT32
- *(ntfs)* implement set_attrs so cross-fs chmod works on NTFS
- *(shell)* add `chmod MODE PATH` + AnyFs::set_attrs wrapper
- *(shell)* quote-aware argument parsing; preserve host timestamps on put

### Fixed

- *(ext)* scan all directory blocks when unlinking an entry ([#29](https://github.com/KarpelesLab/fstool/pull/29))
- *(hfs+)* preserve mtime on symlinks and device nodes
- *(hfs+)* store per-file modification times in catalog records
- *(fat)* store and surface file modification times
- *(exfat)* surface on-disk timestamps in getattr

### Other

- *(cli)* cross-backend chmod end-to-end; fix ntfs set_attrs doc links
- *(ntfs)* pin Everyone-access security descriptor on the put path

## [0.4.17](https://github.com/KarpelesLab/fstool/compare/v0.4.16...v0.4.17) - 2026-06-12

### Fixed

- *(inspect)* drain NTFS/XFS/exFAT dir batches in AnyFs::flush

### Other

- *(inspect)* drop intra-doc link to private as_filesystem_dyn
- *(inspect)* collapse AnyFs::flush + kind_string to exhaustive dispatch

## [0.4.16](https://github.com/KarpelesLab/fstool/compare/v0.4.15...v0.4.16) - 2026-06-12

### Fixed

- *(fstool)* escape image-supplied names on TTY; saturating LBA math (CLI-2, CLI-4)
- *(fstool)* validate image entry names before host path join (CLI-1, CLI-3)
- *(repack,merge)* bound tar walkers and drop `..` in merge (CORE-1, CORE-2)
- *(fs)* guard total_file_bytes against directory cycles (MISC-4)
- *(ramfs)* cap capacity hints and resize ceilings (MISC-3, MISC-5)
- *(grf)* bound read_entry allocation by device size (MISC-2)
- *(iso9660)* bound read_directory allocation by device size (MISC-1)
- *(gpt)* checked_mul for entries_start_lba * 512 (BLK-4)
- *(dmg)* bound attacker-controlled allocations on malformed images
- *(archive)* strip `..` in shared normalise_path to block traversal
- *(lha)* guard short tail reads in the header scan loop
- *(sevenz)* bound untrusted 7z counts and cap encoded-header decode
- *(xfs)* extent-driven dir walk and checked byte-offset math
- *(f2fs)* bound superblock block_count by device capacity (SQF2-5)
- *(squashfs)* bound untrusted allocations and guard short-block underflow
- *(affs)* bound chain walks with range checks + visited-sets (FATX-3, FATX-4, FATX-5)
- *(fat)* bound chain walks by cluster_count, validate sectors_per_cluster (FATX-2, FATX-6)
- *(exfat)* bound cluster-chain walks by ClusterCount (FATX-1)
- *(hfs+)* bound journal replay and validate ring geometry (HFS-2, HFS-3, HFS-5)
- *(hfs+)* guard writer leaf-chain walks and bitmap sizing (HFS-1, HFS-4)
- *(apfs)* harden reader/writer against malformed images
- *(ntfs)* harden malformed-image handling (NTFS-1..5)
- *(ext)* bound extent-append, dx lookup, symlink, and dir scan on malformed input (EXT-4, EXT-5, EXT-6, EXT-8)
- *(ext)* harden indirect/extent tree walks against OOB, cycles, depth (EXT-3, EXT-7)
- *(ext)* cap journal replay at ring size to stop cyclic descriptors (EXT-2)
- *(ext)* bound attacker-controlled group count before allocating (EXT-1)

### Other

- *(fstool)* make safe_component drive-prefix test platform-aware (CLI-1)
- apply rustfmt to security-hardening changes

## [0.4.15](https://github.com/KarpelesLab/fstool/compare/v0.4.14...v0.4.15) - 2026-06-11

### Added

- *(cli)* surface statfs in `fstool info` and add a shell `df` command
- *(ramfs)* `fstool mount --new-ramfs` — mount an in-memory tree over FUSE
- *(ramfs)* AnyFs::Ramfs variant + `fstool shell --new-ramfs` with save
- *(ramfs)* in-memory Filesystem with repack_to + generic walk_filesystem
- *(ntfs)* analytic FsSizePlan + contiguous $MFTMirr for content-fit create
- *(hfs)* analytic FsSizePlan for content-fit classic-HFS create
- *(create)* HFS+ analytic FsSizePlan (catalog B-tree)
- *(create)* F2FS analytic FsSizePlan
- *(create)* XFS analytic FsSizePlan
- *(create)* two-phase analytic builder — FsSizePlan via FilesystemFactory, AFFS reference
- *(create)* writer-determined exact sizing for all block filesystems
- *(create)* exact content-fit sizing infra + FAT32 (FsSizePlan)

### Fixed

- *(hfs+)* fsck-clean create at any size (alt-VH alignment + bitmap padding)

### Other

- *(analyze)* drop the binary-search writer_required_size fallback
- *(hfs+)* drop unresolved intra-doc link to trait method total_size

### Fixed

- *(hfs+)* `create -t hfsplus` now produces `fsck.hfsplus`-clean volumes at
  **any** size, not only block-aligned ones. Two pre-existing writer bugs:
  (1) the image could be a non-multiple of the 4 KiB allocation block (the
  `2× + 64 MiB` auto-size, or an arbitrary `--size`), leaving a trailing
  partial block past the alternate volume header where `fsck` reads a
  misplaced header — `HfsPlus` now reports `image_len`, so the create/repack
  paths truncate the output to a whole number of allocation blocks; (2) when
  the bitmap's last byte was partial, its padding bits were written as `1`,
  but TN1150 requires bits beyond `total_blocks` to read as `0` — they're now
  cleared on disk (the in-memory allocator still keeps them set). Verified
  `fsck.hfsplus`-clean across previously-failing block counts and 500/5000-file
  trees.

### Added

- *(create)* **content-fit sizing, exact per filesystem.** `fstool create
  <fs> <source-dir>` without `--size` now computes the *minimal* image that
  holds the content, instead of a `2× + 64 MiB` over-provision (or, for FAT32,
  requiring `--size`). A new `FsSizePlan` trait (mirroring ext's `BuildPlan`)
  lets each filesystem accumulate the exact on-disk allocation from the single
  analysis walk and return the smallest image its writer accepts, rounded only
  to that filesystem's native unit. **FAT32** is the first wired up: it
  searches the authoritative `Fat32::geometry`, so e.g. 250 MiB of content
  produces a ~254 MiB image (≈1 % overhead, all but one cluster used) and a
  source-backed `create -t fat32` no longer needs `--size`.
- *(create)* **the writer now determines its own size for every block
  filesystem** (hfs+, hfs, affs, xfs, ntfs, f2fs). Rather than a parallel size
  model that could drift, `create <fs> <dir>` (no `--size`) does a dry-run:
  it formats and populates the *real* writer against a sparse, write-discarding
  `SizingDevice` — assigning inodes/CNIDs, encoding names, building B-trees and
  directory blocks exactly as for a real build, with file data written as
  zeros so the probe is metadata-only — and binary-searches the smallest size
  the writer's own allocator accepts. Result: tight, `fsck`-clean images
  (hfs +0 %, affs +1 %, hfs+ +3 %, xfs +13 %; ntfs and f2fs report their
  writers' genuine minimums) versus the former `2× + 64 MiB`. Compressing /
  archive backends (squashfs, iso, grf, …) keep their grow-then-truncate path.
  The probe tolerates writers that *panic* on degenerate small sizes (caught
  and treated as "doesn't fit"), e.g. a pre-existing f2fs format panic.

## [0.4.14](https://github.com/KarpelesLab/fstool/compare/v0.4.13...v0.4.14) - 2026-06-07

### Fixed

- *(xfs)* empty `create` failed with "flush_writes called before begin_writes()"

### Other

- *(changelog)* move xfs fix to [Unreleased], drop release-plz dup blocks

## [0.4.13](https://github.com/KarpelesLab/fstool/compare/v0.4.12...v0.4.13) - 2026-06-07

### Added

- *(shell)* add `get SRC [DEST]` — copy a file/dir out of the image to host
- *(shell)* --with-cache opt-in in-memory inode cache
- *(cli)* fstool dd — resilient raw block copy with live progress

### Fixed

- *(hfs+,fat32)* zero only metadata on format, not the whole device
- *(info)* drop stale "read support is scaffold-only" note (NTFS/F2FS/SquashFS)

### Other

- *(changelog)* move dd entry under [Unreleased] after v0.4.12 release

## [0.4.12](https://github.com/KarpelesLab/fstool/compare/v0.4.11...v0.4.12) - 2026-06-07

### Added

- *(shell)* richer find (time/sort/limit/types) and grep (-v/-l/-c)
- *(shell)* Ctrl-C cancels a running find/grep without killing the shell
- *(shell)* add `find` and `grep` (binary matches as hexdump -C)
- *(affs)* true incremental in-place editing of OFS/FFS images

### Fixed

- *(affs)* reword editor doc comment to avoid clippy doc_lazy_continuation

### Other

- *(apfs)* make README status accurate (read snapshots/xattrs, write via macOS-mount, honest gaps)
- *(qcow2)* clean errors instead of panics in the compressed writer

## [0.4.11](https://github.com/KarpelesLab/fstool/compare/v0.4.10...v0.4.11) - 2026-06-03

### Added

- *(qcow2)* produce compressed images — --compress on create/build/repack/convert
- *(qcow2)* copy-on-write when writing into a compressed cluster
- *(qcow2)* read compressed clusters (zlib + zstd)
- *(affs)* in-place mutation for Amiga OFS/FFS (phase 3)
- *(affs)* Amiga OFS/FFS writer — generate from scratch (phase 2)
- *(affs)* Amiga OFS/FFS read support (phase 1)
- *(hfs)* in-place mutation — open_writable + add/remove (Phase 3)
- *(hfs)* classic-HFS writer — create / build / repack (Phase 2)

### Fixed

- *(hfs)* zero filStBlk in file records (the last fsck error)
- *(hfs)* 46-byte (Str31) thread records + zero FInfo
- *(hfs)* variable even-padded thread records + root directory valence
- *(hfs)* empty B-tree is header-only (extents-overflow file)
- *(hfs)* even-align catalog records + write MDB volume counts
- *(hfs)* index-node B-tree records must use fixed-length keys

### Other

- *(affs)* don't intra-doc-link the private `writer` module
- *(examples)* add Raspberry Pi, EFI, and legacy-BIOS disk specs

### Added

- *(qcow2)* read **compressed clusters** — both zlib/deflate (qemu's default)
  and zstd. So every operation (`info`, `ls`, `cat`, `shell`, `add`, `repack`,
  `convert`, FUSE) now works transparently on compressed qcow2 images such as
  `qemu-img convert -c` output and distro/cloud images. Deflate clusters decode
  with a 4 KiB sliding window (matching qemu's `inflateInit2(-12)` and bounding
  per-cluster RAM); the L2 `COMPRESSED` entry and v3 `compression_type` header
  field are parsed, and a one-cluster decompression cache keeps sequential
  sub-cluster reads cheap. New `src/block/qcow2/compress.rs`; bumps `compcol`
  to 0.6 for its `deflate` window knobs. Cross-checked byte-exact against
  `qemu-img`-produced zlib and zstd images. Writing into a compressed cluster
  copies it out to a plain cluster first (qemu's behaviour) — decompress,
  allocate, repoint the L2 entry, and release the old cluster's (possibly
  shared) host-range refcounts — so `add`/shell edits of a compressed image
  work and stay `qemu-img check`-clean.

- *(qcow2)* **produce** compressed qcow2 images: a `--compress[=SPEC]` flag on
  `create` / `build` / `repack` / `convert` (`--compress`, `--compress=9`,
  `--compress=zstd`, `--compress=zstd:9`) serialises a fresh compressed image —
  each non-zero cluster compressed once (zeros stay sparse), payloads packed
  byte-granularly, with L1/L2/refcount tables (and exact shared-host-cluster
  refcounts) and a header carrying `compression_type` (+ the COMPRESSION_TYPE
  incompatible bit for zstd). Deflate uses a 4 KiB match window so qemu reads
  it. Validated with `qemu-img check` + `qemu-img convert -O raw` byte-exact,
  for both codecs.

- *(affs)* in-place mutation for **Amiga OFS/FFS**: `Affs::open_writable` loads
  an existing `.adf` (every directory plus the bytes of every file) into the
  in-memory tree, so `fstool add` / `rm` and shell `put` / `mkdir` / `rm` edit a
  volume in place — the whole image is re-laid-out (and re-checksummed) on flush,
  preserving untouched files byte-exact. `AnyFs::open_writable` routes AFFS here;
  `list`/`open_file_reader` serve pending edits from the model before flush.

- *(affs)* new **Amiga OFS/FFS** (`.adf`) read + generate support. Reads the
  boot-block variant (`DOS\0`..`DOS\7`: FFS/OFS, International, directory-cache),
  the root block, hash-table directories (and same-hash chains), and files via
  the file header + extension blocks — serving both OFS (24-byte per-block data
  headers, 488 payload bytes) and FFS (raw 512-byte) data. Names decode as
  Latin-1; dates use the Amiga 1978 epoch. **Write**: `fstool create -t affs`
  (or `-t ofs`), `build`, and `repack` generate fresh OFS or FFS volumes
  (default DOS\3 FFS+INTL; `-O fstype=ofs,intl=false` to vary) via an in-memory
  tree serialised block-by-block on flush, with correct block checksums, name
  hashing (ASCII + International), file-extension chaining, and a volume bitmap.
  New `src/fs/affs/` (`mod.rs` reader, `writer.rs`); wired into detection,
  `info`, `ls`, `cat`, `create`, `build`. Layout follows adflib's `adf_blk.h`;
  the reader is validated against real OFS/FFS Workbench volumes and the writer's
  output is checked for block-checksum / hash-slot / bitmap conformance (the
  exact invariants the Linux kernel `affs` driver enforces). In-place mutation
  (`add`/`rm`) lands next.

- *(hfs)* classic-HFS is now **read + write**. `fstool create -t hfs`, `build`,
  and `repack` generate fresh volumes, and `add` / `rm` / shell `put`/`mkdir`
  mutate an existing image **in place** (`Hfs::open_writable` loads the catalog,
  mutations rebuild it, `flush` writes catalog + extents + bitmap + MDB). Ports
  the HFS+ writer's design (catalog as an in-memory `BTreeMap`, on-disk B-trees
  rebuilt by greedy 512-byte node packing) with HFS specifics: MacRoman names +
  case-insensitive catalog collation, MDB + volume bitmap, up-to-3-extent B-tree
  files. New `src/fs/hfs/writer.rs` and `macroman::encode`/`cmp_ci`. Validated by
  reader round-trips (create + in-place; a strict B-tree key-order check) and, on
  macOS CI, `fsck_hfs` (via `hdiutil attach`; the Linux `fsck.hfsplus` segfaults
  on classic HFS — confirmed on a genuine System 6.0.8 volume — so it is not
  used). Classic HFS has no symlinks, so `create_symlink` is `Unsupported`.

## [0.4.10](https://github.com/KarpelesLab/fstool/compare/v0.4.9...v0.4.10) - 2026-05-30

### Added

- *(hfs+)* resource-fork support (read, inventory, decode, extract)
- *(hfs)* resource-fork support — read, inventory, decode, extract
- *(cli)* --path-style {unix|native} + canonical HFS/HFS+ slash handling
- *(cli)* ls -R recursion + readline line editing in the shell
- *(part)* Apple Partition Map (APM) read-only support
- *(hfs)* classic HFS read-only reader (DiskCopy 4.2 floppies, System ≤ 8)
- *(block)* DiskCopy 4.2 container backend (transparent unwrap)
- *(sevenz)* 7-Zip read-only reader (Copy/LZMA/BZip2/Deflate; rest pending compcol)
- *(sit)* StuffIt classic SIT! read-only reader (store; rest pending compcol)
- *(arc)* SEA ARC read-only reader (stored methods; compressed pending compcol)
- *(lha)* LHA/LZH read-only reader (lh0 store; lh-series pending compcol)

### Other

- *(release-plz)* authenticate with RELEASE_PLZ_TOKEN (PAT)
- *(archive)* skip 7z/lha cross-checks when the reference tool misbehaves
- *(archive)* update scaffold test now that 7z/lha/arc/sit decode

### Added

- *(hfs+)* **resource-fork** support for HFS+/HFSX, matching classic HFS:
  `HfsPlus::open_resource_fork_reader` reads the fork via the existing
  fork-type-`0xFF` extent machinery, `cat --rsrc` / `resources` work on HFS+
  files, and `list_xattrs` surfaces `com.apple.ResourceFork`. HFS-compressed
  files are excluded (their resource fork holds `decmpfs` storage, not a user
  resource fork).
- *(hfs)* classic-HFS **resource-fork** support. The reader now reads each
  file's resource fork (its own extents, fork-type `0xFF`) and surfaces it three
  ways: `fstool cat --rsrc <img> <path>` streams the raw fork; a new `fstool
  resources <img> <path>` command parses the resource map and lists every type
  with each resource's id/name/size and a decoded summary for common types
  (`vers`, `STR `, `STR#`, `TEXT`, `ICN#`/`ICON`, `DITL`), with `--extract
  TYPE:ID` to dump one resource; and `list_xattrs` exposes the fork as the
  macOS-standard `com.apple.ResourceFork` xattr (so it shows in `info` and rides
  through `repack`/`add` to xattr-capable targets). New filesystem-agnostic
  `resfork` module + a crate-level `macroman` module (promoted from the HFS
  reader).
- *(cli)* global `--path-style {unix|native}` flag. `unix` (default) separates
  every path with `/` and shows a literal `/` inside an HFS/HFS+ name as `:`
  (the macOS convention); `native` uses the filesystem's own separator (`:` for
  HFS/HFS+, `\` for FAT/exFAT/NTFS, `/` elsewhere) and preserves real
  filenames. Translation happens only at the CLI/shell boundary — readers,
  `repack`, and on-disk formats are unaffected.
- *(cli)* `fstool ls -R` / `--recursive` — walk subdirectories, printing each
  directory under a `path:` header (like `ls -R`). Works on both block-device
  images and streamed `.tar.<algo>` archives; never descends the `.`/`..`
  self/parent links.
- *(shell)* the interactive `fstool shell` now has **line editing and command
  history** on a TTY (↑/↓ to recall, Ctrl-A/E, Ctrl-R reverse search) via
  `rustyline`, with history persisted to `~/.fstool_history`. Behind the
  default-on `readline` feature; piped/non-TTY input keeps the deterministic
  line-buffered reader, and `default-features = false` drops the dependency.
- *(hfs)* classic **HFS** (Hierarchical File System, Mac OS ≤ 8) read-only
  reader — parses the Master Directory Block at offset 1024 (`BD` signature),
  loads the catalog + extents-overflow B-trees into memory (512-byte nodes,
  MacRoman Pascal names) and exposes each file's **data fork**. Resolves nested
  paths and streams file contents via allocation-block extents. Validated
  against a genuine System 6.0.8 disk image (extracts the real System/Finder/
  Read Me contents) plus a synthetic-volume regression test. Resource forks,
  HFS-wrapped HFS+ and creation are unsupported.
- *(block)* **DiskCopy 4.2** container backend — a read-only device wrapper
  that exposes the inner volume (data fork at file offset `0x54`), probed in
  `open_image` after qcow2/dmg so a DiskCopy-wrapped floppy (classic HFS, FAT,
  ISO, …) is detected and read transparently like a raw image.
- *(part)* **Apple Partition Map** (APM) read-only support — the classic Mac /
  PowerPC / `.toast` partitioning scheme. Detected via the Driver Descriptor
  Map (`ER` at block 0) plus the `PM` partition map, surfaced exactly like
  GPT/MBR: `fstool info disk.toast` lists the `Apple_HFS` / `Apple_Free` /
  `Apple_partition_map` entries and `disk.toast:N` slices partition *N* (e.g.
  reading the wrapped classic-HFS volume). Writing an APM is unsupported.

- *(sevenz)* 7-Zip (`.7z`) read-only reader behind the `sevenz` feature —
  parses the full container (32-byte signature header, the optionally
  LZMA-packed `kEncodedHeader` end header, `StreamsInfo` folders/coders/
  substreams and `FilesInfo` UTF-16 names + empty-stream/empty-file vectors)
  and maps every file to its folder substream. Single-coder **Copy / LZMA /
  BZip2 / Deflate** folders decode (solid folders are decoded once and sliced
  per substream; LZMA reuses compcol's `.lzma` decoder via a synthesized
  header), cross-checked against the reference `7z` tool. LZMA2 (the 7-Zip
  default), BCJ/Delta filters, PPMd, encryption and any multi-coder pipeline
  list correctly but read as a clean `Unsupported`, pending a raw-LZMA2 entry
  point + branch-filter codecs in `compcol`. Creation is unsupported. This
  completes the archive table — **no detection-only scaffolds remain**.
- *(sit)* StuffIt (`.sit`) read-only reader behind the `sit` feature — parses
  the **classic** `SIT!` container (22-byte archive header + 112-byte per-file
  entry headers, resource + data forks, big-endian) and indexes every member
  by its data fork, honouring the folder start/end markers for nested paths.
  Data-fork method 0 (store) decodes today; the compressed methods (RLE90,
  LZW, Huffman, LZAH, LZ+Huffman, Arsenic, …) and the entire StuffIt 5 format
  list/detect but read as a clean `Unsupported` pending StuffIt codecs in
  `compcol`. Creation is unsupported.
- *(arc)* SEA ARC (`.arc`) read-only reader behind the `arc` feature — walks
  the flat per-file header chain and indexes every member. The stored methods
  (1 = old, 2 = with an original-size field) decode today; the compressed
  methods (3 RLE90, 4 squeeze, 5–9 crunch/squash) list correctly but read as a
  clean `Unsupported` pending ARC codecs in `compcol`. Creation is unsupported.
- *(lha)* LHA / LZH (`.lzh`, `.lha`) read-only reader behind the `lha` feature
  — walks the header chain at levels 0, 1 and 2 (incl. the level-1 skip-size /
  extended-header math and level-2 ext-header filenames + directory
  components) and indexes every member. `-lh0-` store decodes today
  (cross-checked against the reference `lha` tool with genuine fixtures at all
  three header levels); the lh1/4/5/6/7 LZSS+Huffman methods list correctly but
  read as a clean `Unsupported` pending an `lha` codec in `compcol`. Creation
  is unsupported.

### Changed

- *(inspect)* the "no recognised filesystem" error no longer enumerates every
  supported format — the growing list made the message hard to read. It now
  reads simply `no recognised filesystem or archive on this image`.
- *(hfs, hfs+)* a literal `/` inside a classic-Mac filename (legal there, since
  the separator is `:`) is now canonicalised to `:` on listing and resolution,
  so it can't be mistaken for a path separator. Fixes mis-resolution / `ls -R`
  aborting on real volumes (e.g. a directory named `A/ROSE Includes`), and
  means such names repack into a tar/zip as `A:ROSE Includes`. HFS+ previously
  left the raw `/` in place (latent bug); it now matches classic HFS.

## [0.4.9](https://github.com/KarpelesLab/fstool/compare/v0.4.8...v0.4.9) - 2026-05-30

### Added

- *(dmg)* switch encrypted-DMG crypto to purecrypto
- *(rar)* support solid RAR5 archives, decoding the group once
- *(rar)* RAR5 read-only reader (store + compressed) via compcol::rar5

### Fixed

- *(qcow2)* bound L1 table by file length, not minimum entries
- *(repack)* bound source directory walk against cycles + strip '..'
- *(archive,grf)* bounds-check entry fields and cap untrusted allocations
- *(iso9660,squashfs,tar)* cap untrusted allocations + bound RR/PAX parsing
- *(f2fs,exfat,fat)* cap untrusted-size allocations and validate geometry
- *(apfs)* bound B-tree descent + checked spaceman math against malicious images
- *(hfs+)* harden HFS+ reader against malicious images
- *(xfs)* harden XFS reader against malicious images
- *(ntfs)* harden NTFS reader against malicious images
- *(ext)* harden ext2/3/4 reader against malicious images
- *(block,part)* validate GPT/DMG/qcow2 header fields against malicious images
- *(doc)* drop intra-doc links to private items (cargo doc -D warnings)

### Other

- *(changelog)* record security hardening pass

## [0.4.8](https://github.com/KarpelesLab/fstool/compare/v0.4.7...v0.4.8) - 2026-05-29

### Added

- *(compression)* move lzma to compcol; drop lzma-rs (sole codec backend)
- *(lzx)* Amiga LZX (.lzx) read-only reader via compcol
- *(dmg)* decode bzip2 + LZFSE chunks via compcol; drop bzip2-rs
- *(compression)* move lz4 + lzo to compcol; drop lz4_flex + minilzo-rs
- *(cab)* multi-block MSZIP via compcol 0.4.3 preset dictionary
- *(cab)* read-only Microsoft Cabinet reader via compcol
- *(compression)* retire flate2 — zip/DMG/HFS+ zlib+deflate on compcol
- *(compression)* route gzip/zlib/xz/zstd through compcol
- *(ext4)* arbitrary-depth extent tree writes (rw + streaming)
- *(apfs)* accept hashed-key (case-insensitive) volumes for mutation
- *(apfs)* apfs_drec_name_len_and_hash + DrecKeyLayout in build_drec_record
- *(cli)* fstool shell --ro for safe read-only browsing
- *(apfs)* refuse Apfs::open_writable on case-insensitive volumes
- *(apfs)* wire Filesystem::truncate + override list_xattrs
- *(apfs)* thread mtime through create_*_at + Filesystem create paths
- *(apfs)* wire CLI mutators through Apfs::open_writable
- *(apfs)* ring-buffer the xp_desc area so checkpoints don't exhaust
- *(apfs)* wire Filesystem trait through Write-state mutators
- *(apfs)* Write-state create_file_at / create_dir_at / create_symlink_at + xattr setters

### Fixed

- *(cli)* refuse compressed sources for mutators; refuse streaming FS for shell
- *(apfs)* drop redundant drop(cx) flagged by clippy

### Other

- bump compcol to 0.4.4
- *(cab)* stream folder extraction instead of buffering whole folder
- *(fuzz)* make fuzz core deterministic — BTreeMap instead of HashMap
- *(apfs)* macOS-gated fsck_apfs on hashed-key open_writable creates
- *(apfs)* macOS-gated fsck_apfs run on open_writable create flow
- *(apfs)* fold commit_checkpoint into commit_with_mutator
- *(apfs)* introduce MutatorCx, generalise commit_with_mutator closure
- *(apfs)* extract record builders to pub(crate) free functions

## [0.4.7](https://github.com/KarpelesLab/fstool/compare/v0.4.6...v0.4.7) - 2026-05-27

### Added

- *(ext)* triple-indirect, LARGE_FILE, and prezeroed fast-path
- *(repack)* truncate filename from the left to fit a narrow PTY
- *(repack)* progress bar during the copy phase

### Fixed

- *(qcow2)* keep image sparse for zero writes to unmapped clusters
- *(create)* auto-size from source instead of the 1 MiB default
- *(repack)* reset file counter at each phase, not summed across passes

### Other

- drop private-item intra-doc link in file_block
- cargo fmt the new tests + helper closure

## [0.4.6](https://github.com/KarpelesLab/fstool/compare/v0.4.5...v0.4.6) - 2026-05-27

### Added

- *(merge)* hard links + fix(fat): flush dir batches before read

### Fixed

- *(doc)* resolve merge.rs intra-doc links for `cargo doc -D warnings`
- *(repack)* don't strip Windows drive letters from tar paths

### Other

- *(repack)* unify plain + compressed tar arms in walk_source_into_sink
- *(cli)* stream plain tar sources too — kill the random-access Tar::open
- *(ext)* O(1) data-block allocator via per-group cursor
- *(fat32)* O(1) child_exists via per-parent name index
- *(iso9660)* tree children → BTreeMap, kills O(n²) insert + lookup
- *(f2fs)* lazy `i_addr` Vec — 8× RAM cut on bulk-insert workloads

## [0.4.5](https://github.com/KarpelesLab/fstool/compare/v0.4.4...v0.4.5) - 2026-05-26

### Other

- *(merge)* in-memory model + per-source ordered emission, no tempfile
- *(repack)* stream tar into zip/cpio + tar→tar, drop archive temp files
- *(repack)* stream compressed tar into squashfs/iso/grf, no tempfile
- *(iso9660)* stream file data to the device, no temp file, bounded RAM
- *(grf)* stream body into the archive directly, no temp file
- *(squashfs)* stream file data to the device, no temp files
- *(clone)* buffer small clones in memory instead of a temp file

## [0.4.4](https://github.com/KarpelesLab/fstool/compare/v0.4.3...v0.4.4) - 2026-05-25

### Fixed

- *(ntfs)* size resident $DATA by actual $SI/$FN length (fuzz panic)

### Other

- *(repack)* stop spilling every streamed file to a temp file
- *(hfs+)* bump-cursor allocation — drop O(n²) from large-dir builds
- *(f2fs)* O(1) directory lookups — drop O(n²) from large-dir builds

## [0.4.3](https://github.com/KarpelesLab/fstool/compare/v0.4.2...v0.4.3) - 2026-05-25

### Added

- *(f2fs)* hashed multi-level directories — large dirs pass fsck.f2fs
- *(hfs+)* grow catalog B-tree + correct clump size — 100k files clean
- *(xfs)* 2-level INOBT — 100k+ files in one directory pass xfs_repair
- *(xfs)* leaf + node directories and aligned inode chunks (to ~16k files)
- *(ext4)* incremental depth-2 extent growth for large directories
- *(ext4)* depth-N extent trees + journal/flex_bg sizing for large dirs
- *(analyze)* generic source-analysis API + `fstool analyze` command
- *(repack)* stream compressed-tar sources — no decompress-to-tempfile
- *(repack)* phase markers + wire up the per-file progress counter
- *(shell)* `info <path>` dumps per-file metadata + xattrs

### Fixed

- *(xfs)* escape `bestfree[0]` in doc comment to unbreak cargo doc
- *(xfs)* clean error instead of panic on block-dir overflow
- *(ntfs)* scale directories + $MFT to 100k files (clean ntfs-3g mount)
- *(ext4)* one-shot build path promotes to depth-1 extent tree

### Other

- *(f2fs)* mark large-directory test ignored — known writer limitation
- *(f2fs)* large-directory guard (read-back local, fsck.f2fs in CI)
- *(ntfs)* external scale guard — 4000-file dir mounts ntfsfix-clean
- *(exfat)* batch directory writes via DirBatch + lookup overlay
- *(fat)* batch directory writes via DirBatch + lookup overlay
- *(xfs)* batch directory writes via DirBatch + lookup overlay
- *(ntfs,ext)* batch directory writes; add shared DirBatch cache
- *(squashfs)* multithread block compression by default
- *(repack)* gate compressed-tar stream test to Unix

## [0.4.2](https://github.com/KarpelesLab/fstool/compare/v0.4.1...v0.4.2) - 2026-05-25

### Added

- *(xfs)* refuse open_file_rw on REFLINK files — prevent clone corruption (Phase 3b stage 3)
- *(xfs)* clone_file via shared extents + REFCNTBT records (Phase 3b stage 2)
- *(xfs)* REFLINK feature opt-in + per-AG REFCNTBT root (Phase 3b stage 1)
- *(fs)* clone API — Filesystem::clone_file / clone_range + CloneCapability (Phase 3a)
- *(ntfs)* create_device for char/block via INTX_FILE; sort $I30 entries
- *(hfs+)* create_device — char / block / FIFO / socket nodes
- *(ntfs)* implement remove (file / empty-dir / symlink), the inverse of create
- *(ntfs)* make a reopened image mutable (lazy writer reconstruction)
- *(ntfs)* getattr (times + synthesised mode) and list_xattrs
- *(hfs+)* faithful getattr
- *(iso9660)* faithful getattr from Rock Ridge
- *(apfs)* faithful getattr
- *(archive)* shared archive core + zip/cpio/ar backends, 7 scaffolds

### Fixed

- *(fs)* owned-tempfile FileSource for deferred-write backends; SquashFS getattr

### Other

- fix 5 broken intra-doc links + BSD-ar cross-check on macOS
- *(dmg)* end-to-end against hdiutil on macOS (UDRW / UDZO / UDBZ / ULFO)
- *(fuzz)* NTFS fuzz target + Op::Clone with shares_extents freezing
- F2FS is build-once — correct the in-place-edits column
- cross-backend reopen-mutate sweep; make F2FS advertise build-once
- every repack source reader now surfaces faithful metadata
- move qcow2 / dmg out of the filesystem-support table
- *(repack)* unify pipeline — one walker + sink, no per-pair paths
- lib-level fuzz across 8 mutable backends
- *(ext)* cover multi-open_file_rw write extending file across drops

### Changed

- *(repack)* unified the repack pipeline: one generic source walker feeds
  one of two sinks (a streaming-tar sink or a block-device `Filesystem`
  sink). The per-`(source,dest)`-type copiers are gone — any readable
  source now repacks into any writable destination through a single
  trait-driven path. The only branch is streaming (tar / `.tar.<codec>`)
  vs non-streaming output. Previously-rejected combinations now work
  (e.g. `repack app.zip out.tar`, `repack image.xfs out.tar`).
- *(fs)* `Filesystem` gains `create_file_streaming` (zero-copy body
  streaming, no per-file tempfile; ext/fat32/exfat override it) and a
  batch `set_xattrs`. Faithful `getattr` (real mode/uid/gid/times, and
  xattrs/device numbers where stored) now on tar, f2fs, and XFS sources
  in addition to ext — so repacking from them preserves metadata.

### Added

- *(archive)* shared archive core (`src/fs/archive/`) — an indexed-entry
  model plus a generic read-only `Filesystem` implementation that archive
  formats plug into by supplying a scanner (and, if writable, a builder).
- *(archive)* **zip** — full read (central-directory scan, robust EOCD
  search, ZIP64, Unix mode/symlinks, Shift-JIS/EUC-JP/UTF-8 filename
  detection) and write (Stored + Deflate, CRC-32, ZIP64 when needed).
  Reads archives produced by other tools; output validates with `unzip`.
- *(archive)* **cpio** — read newc/odc + write newc; round-trips through
  system `cpio`.
- *(archive)* **ar** — read GNU + BSD long names, write GNU; round-trips
  through system `ar`. Flat archive (rejects nested paths).
- *(archive)* detection-only scaffolds for **7z, rar, arc, lha, lzx, cab,
  sit** — recognised by `info`, with a clean `Unsupported` on read until
  pure-Rust decoders are wired (per format, behind a future Cargo feature).
- *(cli)* `create -t {zip,cpio,ar}`, `repack --fs-type {zip,cpio,ar}`,
  `build` with `type = "zip"|"cpio"|"ar"`, and `mount` for all archive
  formats; archive output is truncated to its exact length.

## [0.4.1](https://github.com/KarpelesLab/fstool/compare/v0.4.0...v0.4.1) - 2026-05-22

### Added

- *(fuse)* backend-agnostic adapter — mount any Filesystem via FUSE
- *(apfs)* rename, unlink (hardlink-aware), and link()
- *(apfs)* chmod / chown / set_times mutation API
- shared-access wrapper for cross-thread Ext usage (Phase E)
- fuzz harness + crash-injection block device (Phase D)
- *(ext)* inline_data — store small files in the inode
- FUSE adapter — mount ext{2,3,4} images as a userspace filesystem
- *(ext)* post-build mutation API (chmod, chown, set_times, truncate, rename)
- *(ext)* multi-descriptor JBD2 transactions + fix dx_node header
- *(ext)* two-level HTree (dx_node intermediates)
- *(repack)* replay pending JBD2 journal on the source before reading
- *(repack)* preserve sparse files in ext repack
- *(ext)* preserve hard links across repack
- *(ext)* HTree (DIR_INDEX) write-side support for ext4
- *(ext)* multi-block directories, depth-1 extents, repack progress

### Fixed

- *(clippy)* clean up 11 lints exposed by --all-features build
- *(concurrent)* drop unused `FileSource` import from test module
- *(repack)* wire progress sink through tar-output paths

### Other

- *(fuse)* kernel round-trip test via spawn_mount
- fix 7 broken intra-doc links exposed by --all-features doc build
- install libfuse3-dev + pkg-config on Linux for clippy --all-features
- cargo fmt across recent landings

## [0.4.0](https://github.com/KarpelesLab/fstool/compare/v0.3.1...v0.4.0) - 2026-05-21

### Added

- *(cli)* unify create + add -O / [filesystem.options] for FS knobs

### Fixed

- *(spec)* mark FilesystemSpec #[non_exhaustive]

### Other

- *(readme)* refresh FS matrix + limitations for current state

## [0.3.1](https://github.com/KarpelesLab/fstool/compare/v0.3.0...v0.3.1) - 2026-05-21

### Added

- *(ext)* real JBD2 transactions for open_file_rw (Path A)
- *(apfs)* open_file_rw on flushed images via fresh checkpoint COW
- *(xfs)* leaf-form xattrs (read+write) + remove_xattr
- *(hfs+)* decmpfs read support (types 3 + 4 zlib)
- *(ntfs)* real $LogFile LFS records (Path A) for open_file_rw
- *(dmg)* encrcdsa v2 encrypted DMG read support

### Fixed

- *(hfs+)* keep HfsPlusFileReader as struct to preserve public API

### Other

- drop intra-doc links to private items in apfs

## [0.3.0](https://github.com/KarpelesLab/fstool/compare/v0.2.0...v0.3.0) - 2026-05-20

### Added

- *(hfs+)* route flush metadata writes through journal (Path A)
- *(ntfs)* multi-SD $Secure (User + System); defer $LogFile Path A
- *(xfs)* multi-level B-tree dirs + Path A log transactions
- *(ext4)* open_file_rw on depth-1 extent trees
- *(apfs)* populate IP ring, SFQ free-queues, and main-device alloc zone
- *(dmg)* implement ADC, bzip2, LZFSE, and LZMA chunk codecs
- *(hfs+)* real journal transactions (Path A) for open_file_rw
- *(ntfs)* populate $Secure ($SDS/$SDH/$SII) + sort root $I30
- *(xfs)* single-level B-tree directory reader (di_format=BTREE)
- *(ext4)* open_file_rw on depth-0 inline extent trees
- *(dmg)* chunk decoder — zero / raw / zlib over UDIF v4
- *(apfs)* emit a real spaceman bitmap + checkpoint map
- *(fs)* implement open_file_ro for ext/FAT/exFAT/F2FS/HFS+/NTFS/XFS
- *(apfs)* implement Filesystem::open_file_ro
- *(squashfs)* implement Filesystem::open_file_ro
- *(grf)* implement Filesystem::open_file_ro
- *(iso9660)* implement Filesystem::open_file_ro for random-access reads
- *(fs)* add Filesystem::open_file_ro + FileReadHandle
- *(xfs)* implement Filesystem::open_file_rw via clean-unmount bypass
- *(ntfs)* implement Filesystem::open_file_rw for in-place edits
- *(ext3/4)* accept clean-journal images in open_file_rw
- *(hfs+)* implement Filesystem::open_file_rw for in-place edits
- *(f2fs)* implement Filesystem::open_file_rw for in-place edits
- *(ext2)* implement Filesystem::open_file_rw for in-place edits
- *(fat)* implement Filesystem::open_file_rw for in-place edits
- *(exfat)* implement Filesystem::open_file_rw for in-place edits
- *(fs)* add Filesystem::open_file_rw + FileHandle for in-place edits
- *(apfs)* wire library writer through Filesystem trait
- *(hfs+)* make open() return a writable handle for add/rm round-trips
- *(ntfs)* index system files (records 0..=15) in root $I30 on format
- *(exfat)* wire writer into the Filesystem trait
- *(grf)* GRF (Gravity Ragnarok File) read + write + add/rm
- *(fs)* add MutationCapability::WholeFileOnly for future formats
- *(error)* typed Error::RepackOnly for sequential-by-design FSes

### Fixed

- *(hfs+)* clamp VH nextAllocation < totalBlocks for fsck.hfsplus
- *(exfat)* drop unused FileHandle import in open_file_rw tests
- *(iso9660)* emit SUSP SP marker on root's "." dir record
- *(repack)* Source::detect mishandled Windows drive letters

### Other

- replace links to private items with plain backticks
- cargo fmt across drifted files
- *(ext/flex_bg)* tighten leader/follower mapping check + e2fsck-clean
- resume writes from on-disk AGF/AGI/INOBT/BNO after reopen
- *(hfs+)* lock down create_hardlink link-inode invariant
- *(xfs/dir)* cover dahashname, leaf sort, and i8 shortform decode
- *(squashfs)* cover fragment table reader
- *(ext)* end-to-end xattr round-trip through set_xattrs + read_xattrs
- fix broken intra-doc links from public items into pub(crate)
- rustfmt across the tree
- *(error)* split Streaming vs Immutable instead of one RepackOnly
- collapse build-plan walkers through Filesystem::read_symlink

## [0.2.0](https://github.com/KarpelesLab/fstool/compare/v0.1.0...v0.2.0) - 2026-05-20

### Added

- *(inspect)* variant-agnostic public surface — inspect::open + summary
- *(fs)* Filesystem::supports_mutation() gates add/rm cleanly
- *(cli)* repack accepts positional sources — `repack a b … out`
- *(repack)* layered sources with tar-OCI + overlayfs whiteouts
- *(iso9660)* writer + Filesystem trait + repack-to-ISO wiring
- *(iso9660)* read support — PVD + Joliet + Rock Ridge + El Torito
- *(cli,docs)* wire repack to write XFS/HFS+/NTFS/F2FS/SquashFS via the trait
- *(fs)* wire all writable FSes (XFS/HFS+/NTFS/F2FS/SquashFS/FAT32) through one trait

### Other

- collapse sum_*_file_bytes into Filesystem::total_file_bytes
- *(readme)* cover ISO 9660 + layered merge with whiteouts

## [0.1.0](https://github.com/KarpelesLab/fstool/compare/v0.0.5...v0.1.0) - 2026-05-20

### Added

- *(block)* scaffold Apple DMG (UDIF v4) container support
- *(tar)* random-access index + hardlink materialization + tar.<algo>→ext repack
- *(squashfs)* hardlinks + device nodes + multi-fragment + ext-dir promotion
- *(f2fs)* hard links + triple-indirect nodes + multi-block dentry spill
- *(ntfs)* writer — format + create_file/dir/symlink + flush
- *(apfs)* multi-leaf writer + embedded xattrs (read + write)
- *(hfs+)* extents-overflow spill on write + hard links + journal stub
- *(xfs)* journal stub + multi-AG writes + remove + shortform xattrs
- *(ext)* BuildPlan auto-flex_bg + INCOMPAT_64BIT writer + sparse_super2
- *(tar)* TarStreamReader/Writer + CLI streaming integration (no tempfile)
- *(squashfs)* writer + xattr / id-table / export-table coverage
- *(f2fs)* writer (format, create_file/dir/symlink/device, remove, flush)
- *(ntfs)* fill read-side holes (attr-list, $Secure, $UpCase, LZNT1)
- *(apfs)* multi-volume + snapshots (read) + minimal writer
- *(hfs+)* writer (format, create_dir/file/symlink, remove, flush)
- *(xfs)* B+tree directories + write support (format, add_file/dir/symlink/device)
- *(ext)* flex_bg writer (opt-in via FormatOpts)
- *(compression)* codec features for squashfs reads and tar I/O

### Fixed

- *(hfs+)* drop intra-doc link from public to private fold_case
- *(hfs+)* make fsck.hfsplus accept writer output end-to-end
- *(hfs+)* mark Private Data dir invisible in Finder (frFlags |= kIsInvisible)
- *(hfs+)* set HasLinkChain / HasChildLink flags on hardlink records
- *(hfs+)* iNode files need fileType='iNod' / creator='hfs+' + link count
- *(hfs+)* catalog case-folding compare ignores NUL code units
- *(hfs+)* map record fills the rest of the header node
- *(hfs+)* empty B-trees need a header AND one empty leaf node
- *(hfs+)* B-tree forks need clumpSize ≥ nodeSize
- *(f2fs)* populate valid_node/inode/free_segment counts in CP head
- *(f2fs)* SIT valid_map is MSB-first, not LSB-first
- *(f2fs)* I_ADDR_OFFSET must be 0x168 (kernel spec), not 0xD0
- *(f2fs)* inline-dentry INLINE_RESERVED_SIZE is 7 bytes, not 1
- *(f2fs)* inline payload starts at i_addr[1], not i_addr[0]
- *(f2fs)* emit "." and ".." dentries + correct i_blocks
- *(f2fs)* real curseg layout + SIT type bits + node_footer
- *(f2fs)* NAT entries for node_ino / meta_ino + drop bogus NAT/SIT/SSA CRC
- *(f2fs)* write 8-block CP pack + drop bogus reserved-nid NAT entries
- *(f2fs)* SIT segment count must be even + derive bitmap size from geometry
- *(f2fs)* non-zero rsvd / overprov segments + correct user_block_count
- *(f2fs)* write CP footer at end of pack + correct CP flag values
- *(f2fs)* use real crc32_le(F2FS_SUPER_MAGIC, …) + correct CP field offsets
- *(f2fs)* segment0_blkaddr = cp_blkaddr + ignore reverse-read test
- *(f2fs,ci)* correct f2fs SB field offsets + drop deprecated brew ntfs-3g

### Other

- rustfmt insert_journal_entry signature
- *(readme)* update FS support table for current writer coverage
- Revert "fix(hfs+): catalog case-folding compare ignores NUL code units"
- *(hfs+)* diagnostic also tries mkfs.hfsplus (hfsprogs spelling)
- *(hfs+)* add diagnostic test to dump mkfs vs fstool extents header
- rustfmt write.rs after CP-pack restructure
- *(fs)* native-tool external validation for exfat/xfs/hfs+/apfs/ntfs/f2fs/squashfs + codec fixes
- *(release-plz)* fix release-binaries dispatch (tag schema + actions:write)
- cargo fmt --all

## [0.0.5](https://github.com/KarpelesLab/fstool/compare/v0.0.4...v0.0.5) - 2026-05-19

### Added

- *(fs)* fill out xfs/hfs+/apfs/ntfs/f2fs/squashfs read paths + exfat writer
- *(fs)* xfs/exfat/hfs+/apfs read-only + ntfs/f2fs/squashfs scaffolds
- *(tar)* tar as a read/write filesystem — ext↔tar / fat↔tar repack

### Other

- gate Unix-only integration tests for the Windows / macOS matrix
- *(release-plz)* chain release-binaries via workflow_dispatch

## [0.0.4](https://github.com/KarpelesLab/fstool/compare/v0.0.3...v0.0.4) - 2026-05-19

### Added

- *(ext)* xattr support — read inline + block, write block, preserve on repack
- *(cli)* convert + repack — byte-copy and FS-aware resize
- *(block, cli)* qcow2 write + create — Phase B
- *(block)* qcow2 read path — Phase A
- *(cli)* partition-aware target syntax — disk.img:N
- *(block, cli)* real block-device support on Unix
- *(cli)* fstool shell — interactive REPL over any image
- *(ext4)* sparse_super on the write path
- *(fat32, cli)* modify-in-place — add files, add dirs, remove entries
- *(fat32, cli)* read-side parity — FAT32 reader + unified CLI dispatch

### Fixed

- *(cli)* repack as a direct FS-to-FS copy, no host tempdir

### Other

- release-binaries workflow — five archives per release

## [0.0.3](https://github.com/KarpelesLab/fstool/compare/v0.0.2...v0.0.3) - 2026-05-19

### Added

- *(fat32)* write-path FAT32 filesystem + spec/CLI/CI integration
- *(ext)* automatic sparse files — all-zero blocks become holes
- *(cli)* fstool rm — remove a file / symlink / device / empty directory
- *(cli)* fstool add — copy a host file or directory into an image
- *(ext4)* full metadata_csum write path — ext4 emits checksummed images

### Other

- bring README up to date with phases 4-5 + ext4 features
- metadata_csum foundation — csum module + superblock checksum

## [0.0.2](https://github.com/KarpelesLab/fstool/compare/v0.0.1...v0.0.2) - 2026-05-19

### Added

- *(ext4)* read INCOMPAT_64BIT images — 64-byte group descriptors
- *(spec)* partitioned disk-image build + multi-group ext allocation
- *(spec)* TOML image spec + `fstool build` (bare-filesystem mode)
- *(cli)* add fstool subcommands — ext-build / ls / cat / info
- *(ext4)* write extent-tree inodes (INCOMPAT_EXTENTS) + read them back

### Other

- lazy-stage parent inode + dir block on add_*, enabling modify-after-open
- add release-plz workflow for automated releases
- add CI / crates.io / docs.rs badges to README
