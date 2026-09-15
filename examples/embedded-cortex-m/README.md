# fstool on a Cortex-M4F, without an OS

Three `#![no_std] #![no_main]` programs, each pulling in one of fstool's
allocator-free or allocator-backed drivers. All of them format a volume on
RAM-backed storage, create a file, list a directory and read the file back.
They exist to prove the crate builds and links for a real microcontroller
target, and to measure what it costs.

| binary | feature | fstool features | driver | heap |
|--------|---------|-----------------|--------|------|
| `fstool-embedded-cortex-m` | `alloc-demo` (default) | `fat`, `alloc` | `fs::fat::Fat32` | 64 KiB bump allocator |
| `fstool-embedded-heapless` | `heapless` | `fat`, `exfat` | `fs::fat::Volume` + `fs::exfat::Volume` | **none** |
| `fstool-embedded-littlefs` | `heapless-littlefs` | `littlefs` | `fs::littlefs::Volume` | **none** |

The last two are the interesting ones: they define no
`#[global_allocator]` and never link the `alloc` crate, so if anything
reachable behind the `fat`, `exfat` or `littlefs` features ever started
allocating, they would stop linking. That is a compile-time guarantee, not a
runtime check, and CI builds both on every push.

The heapless binary works the card twice: once through the FAT driver's own
API, then the way a card reader has to — `fstool::fs::mount` probes the card,
hands back whichever volume it found, and a function written once against the
`fs::volume` traits appends to a log on it. That links the exFAT driver into
the same allocator-free program too.

```sh
rustup target add thumbv7em-none-eabihf
cd examples/embedded-cortex-m
cargo build --release                                   # the allocator one
cargo build --release --no-default-features --features heapless
cargo build --release --no-default-features --features heapless-littlefs
# with the llvm-tools component (or arm-none-eabi-size / cargo-binutils):
$(rustc --print sysroot)/lib/rustlib/*/bin/llvm-size \
    target/thumbv7em-none-eabihf/release/fstool-embedded-cortex-m
```

Measured on 2026-09-13 (Rust 1.98, `opt-level = "z"`, fat LTO,
`panic = "abort"`), `.text` for the whole program — the FAT driver with
format + create + list + read, `core::fmt`, and a 64 KiB bump allocator:

| opt-level | `.text` |
|-----------|---------|
| `"z"`     | ~50 KB  |
| `"s"`     | ~54 KB  |
| `3`       | ~65 KB  |

(The heapless driver is compiled into this build too — `fat` enables both
— but nothing references it, so LTO drops every byte: the binary carries
no symbols from the allocation-free driver at all.)

`.bss` is the 64 KiB allocator arena plus a few words; the driver itself
keeps the allocation table and one cluster resident.

The heapless binary, measured the same way on 2026-09-15, is **~39.6 KB** of
`.text` — the FAT driver with its formatter, the MBR and GPT readers, the
probe, and, because the generic append can land on either filesystem, the
exFAT driver's write path as well as its mount — and its `.bss` is just the
512 KiB RAM card. The FAT formatter is about 2.7 KB of that. (Mounting through
the exFAT driver alone, before `fs::mount` existed, was ~23.6 KB: reading a
card costs far less than being able to format and write to both kinds.) Each driver's own state is
one sector of scratch plus the handles you hold, so on real hardware reading
an SD card either costs well under 1 KiB of RAM regardless of how large the
card is.

GPT support is about 700 bytes of that, because the header's CRC-32 goes
through `crc::crc32_small` — bit by bit, no tables. The table-driven `crc32`
the hosted filesystems use would have added 8 KiB of lookup tables to check a
92-byte header.

The littlefs binary, measured the same way on 2026-09-13, is **~28 KB** of
`.text` — format, `mkdir`, write, a user attribute, read, a listing and a
remount — and its `.bss` is the 128 KiB RAM "flash" plus the driver's own
state: one block of scratch (4 KiB here, the erase block), a 256-byte
staging buffer for the commit being programmed, and a 32-byte allocation
window. That footprint does not grow with the size of the flash. Like the
heapless card binary, it formats with the driver itself: `Volume::format` is
right there, whichever filesystem it is.

There is no board support here: `reset` is the entry point named in
`link.x`, the vector table is left to you, and the allocator is the
simplest thing that works. Replace the `MemoryBackend` with a
[`SectorDevice`](../../src/block/sector.rs) over your SD/SDIO driver to
mount a real card, or the `RamFlash` in `heapless_littlefs.rs` with a
[`FlashDriver`](../../src/fs/littlefs/volume/mod.rs) over your QSPI
peripheral to mount real flash.
