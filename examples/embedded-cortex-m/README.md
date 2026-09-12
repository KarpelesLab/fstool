# fstool on a Cortex-M4F, without an OS

A `#![no_std] #![no_main]` program that pulls in fstool with only the `fat`
feature, formats a FAT12 volume on a RAM-backed "card", creates a file,
lists the root and reads the file back. It exists to prove the `no_std`
core builds and links for a real microcontroller target, and to measure
what it costs.

```sh
rustup target add thumbv7em-none-eabihf
cd examples/embedded-cortex-m
cargo build --release
# with the llvm-tools component (or arm-none-eabi-size / cargo-binutils):
$(rustc --print sysroot)/lib/rustlib/*/bin/llvm-size \
    target/thumbv7em-none-eabihf/release/fstool-embedded-cortex-m
```

Measured on 2026-09-13 (Rust 1.98, `opt-level = "z"`, fat LTO,
`panic = "abort"`), `.text` for the whole program — the FAT driver with
format + create + list + read, `core::fmt`, and a 64 KiB bump allocator:

| opt-level | `.text` |
|-----------|---------|
| `"z"`     | ~45 KB  |
| `"s"`     | ~49 KB  |
| `3`       | ~60 KB  |

`.bss` is the 64 KiB allocator arena plus a few words; the driver itself
keeps the allocation table and one cluster resident.

There is no board support here: `reset` is the entry point named in
`link.x`, the vector table is left to you, and the allocator is the
simplest thing that works. Replace the `MemoryBackend` with a
[`SectorDevice`](../../src/block/sector.rs) over your SD/SDIO driver to
mount a real card.
