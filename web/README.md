# fstool web UI

A Vue 3 + Vite single-page app that runs fstool as WebAssembly. Two modes,
both entirely client-side — nothing is uploaded, every byte is processed
locally in WebAssembly memory:

- **Inspect** — drop in an archive or disk image, browse what's inside,
  extract individual files, convert the whole thing to another format.
- **Create** — format a blank filesystem (15 types) or lay out a partitioned
  disk (MBR/GPT, one filesystem per partition), add files and folders, and
  download the image at any point. You can keep editing and download again.

## Architecture

```
web/
├── index.html              Vite entry
├── vite.config.js          base=/fstool/, wasm + top-level-await plugins
├── package.json
└── src/
    ├── main.js
    ├── App.vue             mode switch: inspect flow / builder
    ├── components/
    │   ├── TreeNode.vue    recursive, lazy-loading directory tree (inspect)
    │   └── Builder.vue     create → partition editor → file browser → download
    ├── fstool.js           Web Worker client + shared helpers
    ├── fstool.worker.js    owns the wasm module + open image
    ├── style.css
    └── wasm/               wasm-bindgen output (git-ignored, built by CI)
```

The wasm runs in a **Web Worker** so heavy inspect/convert/format work never
freezes the UI. The worker imports the wasm-bindgen module (built from the
`fstool` crate's `wasm` feature, `bundler` target) and exposes two in-memory
APIs:

- reading — `fstool::memconv`: `probe(bytes)`, `new Image(bytes)` /
  `Image.openPartition(bytes, n)`, `image.list/readFile/convert`,
  `supported_targets()`.
- authoring — `fstool::memedit`: `creatable_filesystems()`,
  `Workspace.newFilesystem/newDisk/fromBytes`, `addPartition`,
  `openPartition`, `list/readFile/addFile/mkdir/remove`, `info`, `export`.

The `Workspace` owns the whole image in Rust and checks out one filesystem at
a time; edits are spliced back into the disk on export or when another
partition is opened, so "the bytes you download are the bytes you edited" is
an invariant of the Rust type rather than something the UI has to maintain.

## Building locally

Requires the `wasm32-unknown-unknown` target, a matching `wasm-bindgen-cli`
(the version pinned in the root `Cargo.toml`), and Node 20+.

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.121   # match the crate

# from the repo root — build the wasm and generate bindings into web/src/wasm:
cargo build --release --lib --target wasm32-unknown-unknown \
  --no-default-features \
  --features wasm,gzip,xz,lzma,lz4,zstd,lzo,cab,amiga-lzx,lha,arc,sit,sevenz,rar,dmg-bzip2,dmg-lzfse,dmg-encrypted
wasm-bindgen --target bundler --no-typescript \
  --out-dir web/src/wasm \
  target/wasm32-unknown-unknown/release/fstool.wasm

# then the site:
cd web
npm install
npm run dev        # dev server with HMR
# or: npm run build && npm run preview
```

`npm run dev`/`preview` serve under the `/fstool/` base (matching GitHub
Pages). To serve at the root instead, set `BASE_PATH=/`.

## Deployment

`.github/workflows/pages.yml` rebuilds the wasm + site and publishes `web/dist`
to GitHub Pages on every push to `master` touching `src/`, `web/`, or
`Cargo.toml`.

## Limits

Everything is held in RAM, so practical image size is bounded by the browser
tab's memory (typically a few hundred MB). `export()` copies the image out of
wasm memory, so a download briefly needs room for two copies. Formats hard-wired to `std::fs`
(qcow2, dmg) are not yet available in the browser — their backends need to be
made device-generic first; see `fstool::memconv` docs.
