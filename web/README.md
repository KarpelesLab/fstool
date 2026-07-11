# fstool web UI

A Vue 3 + Vite single-page app that runs fstool as WebAssembly. Upload an
archive or disk image, browse what's inside, extract individual files, and
convert the whole thing to another format — all in the browser. Nothing is
uploaded; every byte is processed locally in WebAssembly memory.

## Architecture

```
web/
├── index.html              Vite entry
├── vite.config.js          base=/fstool/, wasm + top-level-await plugins
├── package.json
└── src/
    ├── main.js
    ├── App.vue             upload → probe → partition picker → tree + convert
    ├── components/
    │   └── TreeNode.vue    recursive, lazy-loading directory tree
    ├── fstool.js           Web Worker client + shared helpers
    ├── fstool.worker.js    owns the wasm module + open image
    ├── style.css
    └── wasm/               wasm-bindgen output (git-ignored, built by CI)
```

The wasm runs in a **Web Worker** so heavy inspect/convert work never freezes
the UI. The worker imports the wasm-bindgen module (built from the `fstool`
crate's `wasm` feature, `bundler` target) and exposes fstool's in-memory API
(`fstool::memconv`): `probe(bytes)`, `new Image(bytes)` /
`Image.openPartition(bytes, n)`, `image.list/readFile/convert`,
`supported_targets()`.

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

Everything is held in RAM, so practical input size is bounded by the browser
tab's memory (typically a few hundred MB). Formats hard-wired to `std::fs`
(qcow2, dmg) are not yet available in the browser — their backends need to be
made device-generic first; see `fstool::memconv` docs.
