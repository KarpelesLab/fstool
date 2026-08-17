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
//!
//! [`Workspace`] is the authoring half — build an image instead of reading
//! one, and download it at any point:
//!
//! ```js
//! import { creatable_filesystems, Workspace } from './wasm/fstool.js';
//! const ws = Workspace.newDisk(256 * 1024 * 1024, 'gpt');
//! ws.addPartition(48 * 1024 * 1024, 'esp', 'EFI', 'fat32', '');
//! ws.addFile('/EFI/BOOT/BOOTX64.EFI', bytes);
//! const disk = ws.export();                           // Uint8Array
//! ```

use wasm_bindgen::prelude::*;

use crate::memconv::{self, MemImage};
use crate::memedit;

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

/// The filesystems [`Workspace`] can format from scratch, as JSON. Each
/// item: `{ id, label, min_size, default_size, editable, options }`.
#[wasm_bindgen]
pub fn creatable_filesystems() -> Result<String, JsValue> {
    serde_json::to_string(&memedit::creatable_filesystems()).map_err(to_js)
}

/// An image being authored in the browser: a blank filesystem or a
/// partitioned disk, editable and downloadable at any point.
///
/// The whole image lives in wasm memory. `export()` copies it out, so a
/// download costs one extra copy of the image — keep disk sizes sane.
#[wasm_bindgen]
pub struct Workspace {
    inner: memedit::Workspace,
}

#[wasm_bindgen]
impl Workspace {
    /// Format a blank `fsType` filesystem of `size` bytes and open it for
    /// editing. `options` is a `-O`-style `key=val,key=val` string (`""`
    /// for defaults).
    #[wasm_bindgen(js_name = newFilesystem)]
    pub fn new_filesystem(fs_type: &str, size: f64, options: &str) -> Result<Workspace, JsValue> {
        Ok(Workspace {
            inner: memedit::Workspace::new_filesystem(fs_type, size_arg(size)?, options)
                .map_err(to_js)?,
        })
    }

    /// A blank whole-disk image of `size` bytes carrying an empty `table`
    /// (`"gpt"` or `"mbr"`). Add partitions with `addPartition`.
    #[wasm_bindgen(js_name = newDisk)]
    pub fn new_disk(size: f64, table: &str) -> Result<Workspace, JsValue> {
        Ok(Workspace {
            inner: memedit::Workspace::new_disk(size_arg(size)?, table).map_err(to_js)?,
        })
    }

    /// Adopt an existing image (a partitioned disk or a bare filesystem)
    /// for editing.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Workspace, JsValue> {
        Ok(Workspace {
            inner: memedit::Workspace::from_bytes(bytes).map_err(to_js)?,
        })
    }

    /// Append a partition and, when `fsType` is non-empty, format it.
    /// A `size` of `0` claims all remaining space. Returns the new
    /// 1-indexed partition number.
    #[wasm_bindgen(js_name = addPartition)]
    pub fn add_partition(
        &mut self,
        size: f64,
        kind: &str,
        name: &str,
        fs_type: &str,
        fs_options: &str,
    ) -> Result<usize, JsValue> {
        let size = if size <= 0.0 {
            None
        } else {
            Some(size_arg(size)?)
        };
        let name = if name.is_empty() { None } else { Some(name) };
        self.inner
            .add_partition(size, kind, name, fs_type, fs_options)
            .map_err(to_js)
    }

    /// Format partition `index` (1-based) with a blank `fsType` and leave
    /// it open for editing.
    #[wasm_bindgen(js_name = formatPartition)]
    pub fn format_partition(
        &mut self,
        index: usize,
        fs_type: &str,
        fs_options: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .format_partition(index, fs_type, fs_options)
            .map_err(to_js)
    }

    /// Check out partition `index` (1-based) for editing. Pending edits to
    /// the previously-open partition are flushed back into the disk first.
    #[wasm_bindgen(js_name = openPartition)]
    pub fn open_partition(&mut self, index: usize) -> Result<(), JsValue> {
        self.inner.open_partition(index).map_err(to_js)
    }

    /// Describe the workspace as JSON: `{ table, size, partitions,
    /// open_partition, open_fs, open_editable, free_bytes }`.
    pub fn info(&mut self) -> Result<String, JsValue> {
        let info = self.inner.info().map_err(to_js)?;
        serde_json::to_string(&info).map_err(to_js)
    }

    /// List a directory of the open filesystem. JSON `[{ name, kind, size }, …]`.
    pub fn list(&mut self, path: &str) -> Result<String, JsValue> {
        let entries = self.inner.list(path).map_err(to_js)?;
        serde_json::to_string(&entries).map_err(to_js)
    }

    /// Read a whole file out of the open filesystem.
    #[wasm_bindgen(js_name = readFile)]
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, JsValue> {
        self.inner.read_file(path).map_err(to_js)
    }

    /// Create (or replace) a regular file holding `bytes`.
    #[wasm_bindgen(js_name = addFile)]
    pub fn add_file(&mut self, path: &str, bytes: Vec<u8>) -> Result<(), JsValue> {
        self.inner.add_file(path, bytes).map_err(to_js)
    }

    /// Create a directory. Parent directories must already exist.
    pub fn mkdir(&mut self, path: &str) -> Result<(), JsValue> {
        self.inner.mkdir(path).map_err(to_js)
    }

    /// Remove a file, symlink, device node, or empty directory.
    pub fn remove(&mut self, path: &str) -> Result<(), JsValue> {
        self.inner.remove(path).map_err(to_js)
    }

    /// Flush every pending edit and return the whole image. The workspace
    /// stays usable, so this can be called as often as the user likes.
    pub fn export(&mut self) -> Result<Vec<u8>, JsValue> {
        self.inner.export().map_err(to_js)
    }
}

/// Byte sizes cross the JS boundary as `f64` (JavaScript has no u64).
/// Reject anything that isn't a non-negative integer inside the range a
/// double represents exactly, rather than silently truncating.
fn size_arg(size: f64) -> Result<u64, JsValue> {
    if !size.is_finite() || size < 0.0 || size.fract() != 0.0 {
        return Err(JsValue::from_str(&format!(
            "size must be a non-negative whole number of bytes (got {size})"
        )));
    }
    if size > 9_007_199_254_740_991.0 {
        return Err(JsValue::from_str(
            "size exceeds the largest integer a JavaScript number represents exactly",
        ));
    }
    Ok(size as u64)
}
