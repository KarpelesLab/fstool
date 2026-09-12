# fstool on a Cortex-M4F, without an OS

Two `#![no_std] #![no_main]` programs, each pulling in one of fstool's two
FAT drivers. Both format a volume on a RAM-backed "card", create a file,
list the root and read the file back. They exist to prove the crate builds
and links for a real microcontroller target, and to measure what it costs.

| binary | feature | fstool features | driver | heap |
|--------|---------|-----------------|--------|------|
| `fstool-embedded-cortex-m` | `alloc-demo` (default) | `fat`, `alloc` | `fstool::fs::fat` | 64 KiB bump allocator |
| `fstool-embedded-heapless` | `heapless` | `fat` | `fstool::noalloc::fat` | **none** |

The second one is the interesting one: it defines no `#[global_allocator]`
and never links the `alloc` crate, so if anything reachable behind the
`fat` feature ever started allocating, it would stop linking.
That is a compile-time guarantee, not a runtime check, and CI builds it on
every push.

```sh
rustup target add thumbv7em-none-eabihf
cd examples/embedded-cortex-m
cargo build --release                                   # the allocator one
cargo build --release --no-default-features --features heapless
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
no `noalloc` symbols at all.)

`.bss` is the 64 KiB allocator arena plus a few words; the driver itself
keeps the allocation table and one cluster resident.

The heapless binary, measured the same way on 2026-09-13, is **~19 KB** of
`.text` — it carries the FAT12 layout code this example writes by hand as
well as the driver — and its `.bss` is just the 512 KiB RAM card. The
driver's own state is one sector of scratch plus the handles you hold, so
on real hardware reading an SD card it costs well under 1 KiB of RAM
regardless of how large the card is.

There is no board support here: `reset` is the entry point named in
`link.x`, the vector table is left to you, and the allocator is the
simplest thing that works. Replace the `MemoryBackend` with a
[`SectorDevice`](../../src/block/sector.rs) over your SD/SDIO driver to
mount a real card.
