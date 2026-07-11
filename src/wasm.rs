//! WebAssembly bindings for fstool's in-memory inspect/convert surface.
//!
//! Everything runs client-side in the browser: an uploaded file's bytes are
//! handed in as a `Uint8Array`, probed / browsed / converted entirely in
//! WebAssembly memory, and the result handed back as a `Uint8Array` for
//! download. No file ever leaves the page.
//!
//! Built as the `fstool` crate's `cdylib` for `wasm32-unknown-unknown` with
//! `--features wasm`, then post-processed by `wasm-bindgen`. The generated ES
//! module (`bundler` target) initialises the wasm on import, so JavaScript
//! just imports and calls:
//!
//! ```js
//! import { probe, supported_targets, Image } from './wasm/fstool.js';
//! const report = JSON.parse(probe(bytes));           // { compression, partition_table, filesystem, content_size }
//! const img = new Image(bytes);                       // throws on unrecognised input
//! const entries = JSON.parse(img.list('/'));          // [{ name, kind, size }, …]
//! const fileBytes = img.readFile('/etc/hostname');    // Uint8Array
//! const out = img.convert('tar.gz');                  // Uint8Array
//! ```

use wasm_bindgen::prelude::*;

use crate::memconv::{self, MemImage};

/// Install a panic hook that surfaces Rust panics in the browser console.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

fn to_js(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Probe a blob: outer compression, partition table (with each partition's
/// filesystem), or the top-level filesystem/archive kind. Returns JSON.
#[wasm_bindgen]
pub fn probe(bytes: &[u8]) -> Result<String, JsValue> {
    let report = memconv::probe(bytes).map_err(to_js)?;
    serde_json::to_string(&report).map_err(to_js)
}

/// The list of conversion targets the UI can offer, as JSON. Each item:
/// `{ id, label, ext, streaming }`.
#[wasm_bindgen]
pub fn supported_targets() -> Result<String, JsValue> {
    serde_json::to_string(&memconv::supported_targets()).map_err(to_js)
}

/// An opened image or archive, browsable and convertible.
#[wasm_bindgen]
pub struct Image {
    inner: MemImage,
}

#[wasm_bindgen]
impl Image {
    /// Open a blob (auto-detecting format + outer compression). For a
    /// whole-disk image, opens the first partition carrying a recognised
    /// filesystem. Throws if nothing is recognised.
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Result<Image, JsValue> {
        Ok(Image {
            inner: MemImage::open(bytes).map_err(to_js)?,
        })
    }

    /// Open a specific 1-indexed partition of a whole-disk image.
    #[wasm_bindgen(js_name = openPartition)]
    pub fn open_partition(bytes: Vec<u8>, part: usize) -> Result<Image, JsValue> {
        Ok(Image {
            inner: MemImage::open_partition(bytes, Some(part)).map_err(to_js)?,
        })
    }

    /// The filesystem kind (`"ext4"`, `"tar"`, `"iso9660"`, …).
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.inner.kind().to_string()
    }

    /// List a directory (`"/"` for the root). Returns JSON:
    /// `[{ name, kind, size }, …]`.
    pub fn list(&mut self, path: &str) -> Result<String, JsValue> {
        let entries = self.inner.list(path).map_err(to_js)?;
        serde_json::to_string(&entries).map_err(to_js)
    }

    /// Read a whole regular file out of the image (returns a `Uint8Array`).
    #[wasm_bindgen(js_name = readFile)]
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, JsValue> {
        self.inner.read_file(path).map_err(to_js)
    }

    /// Read a symlink's target.
    #[wasm_bindgen(js_name = readSymlink)]
    pub fn read_symlink(&mut self, path: &str) -> Result<String, JsValue> {
        self.inner.read_symlink(path).map_err(to_js)
    }

    /// Convert the whole image/archive to `target` (a format id from
    /// [`supported_targets`]). Returns the finished bytes as a `Uint8Array`.
    pub fn convert(&mut self, target: &str) -> Result<Vec<u8>, JsValue> {
        self.inner.convert(target).map_err(to_js)
    }
}
