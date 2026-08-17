// Thin client over the fstool Web Worker: an id-based request/response
// protocol wrapping postMessage in promises.

export class Fstool {
  constructor() {
    this.worker = new Worker(new URL('./fstool.worker.js', import.meta.url), {
      type: 'module',
    })
    this.seq = 0
    this.pending = new Map()
    this.worker.onmessage = (e) => {
      const { id, ok, result, error } = e.data
      const p = this.pending.get(id)
      if (!p) return
      this.pending.delete(id)
      ok ? p.resolve(result) : p.reject(new Error(error))
    }
  }

  #call(cmd, args, transfer = []) {
    const id = ++this.seq
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      this.worker.postMessage({ id, cmd, args }, transfer)
    })
  }

  // Hand the uploaded file to the worker (transferring the buffer) and probe.
  load(buffer) {
    return this.#call('load', { buffer }, [buffer])
  }
  targets() {
    return this.#call('targets')
  }
  open(part) {
    return this.#call('open', part ? { part } : {})
  }
  list(path) {
    return this.#call('list', { path })
  }
  read(path) {
    return this.#call('read', { path })
  }
  convert(target) {
    return this.#call('convert', { target })
  }

  // Authoring — build an image instead of reading one. Every workspace
  // call that changes the layout resolves with the fresh `info()`, so the
  // caller never has to follow up with a separate query.
  fsTypes() {
    return this.#call('fsTypes')
  }
  newFilesystem(fsType, size, options = '') {
    return this.#call('newFilesystem', { fsType, size, options })
  }
  newDisk(size, table) {
    return this.#call('newDisk', { size, table })
  }
  editLoaded() {
    return this.#call('editLoaded')
  }
  addPartition({ size = 0, kind, name = '', fsType = '', fsOptions = '' }) {
    return this.#call('addPartition', { size, kind, name, fsType, fsOptions })
  }
  formatPartition(index, fsType, fsOptions = '') {
    return this.#call('formatPartition', { index, fsType, fsOptions })
  }
  openPartition(index) {
    return this.#call('openPartition', { index })
  }
  wsInfo() {
    return this.#call('wsInfo')
  }
  wsList(path) {
    return this.#call('wsList', { path })
  }
  wsRead(path) {
    return this.#call('wsRead', { path })
  }
  // `bytes` is an ArrayBuffer; it is transferred, not copied.
  wsAddFile(path, bytes) {
    return this.#call('wsAddFile', { path, bytes }, [bytes])
  }
  wsMkdir(path) {
    return this.#call('wsMkdir', { path })
  }
  wsRemove(path) {
    return this.#call('wsRemove', { path })
  }
  wsExport() {
    return this.#call('wsExport')
  }
  wsClose() {
    return this.#call('wsClose')
  }
}

// Shared UI helpers -------------------------------------------------------

export function humanSize(n) {
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let i = 0
  let v = n
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024
    i++
  }
  return (i === 0 ? v : v.toFixed(v < 10 ? 2 : 1)) + ' ' + u[i]
}

// Directories first, then alphabetical.
export function sortEntries(entries) {
  return [...entries].sort(
    (a, b) =>
      (a.kind === 'dir' ? 0 : 1) - (b.kind === 'dir' ? 0 : 1) ||
      a.name.localeCompare(b.name),
  )
}

export function joinPath(dir, name) {
  return dir === '/' ? '/' + name : dir + '/' + name
}

export function baseName(name) {
  return name
    .replace(/\.(gz|xz|zst|zstd|lz4|lzma|lzo|bz2)$/i, '')
    .replace(/\.[^.]+$/, '')
}

// Parse a size the user typed: a bare byte count, or a number with a
// KiB/MiB/GiB suffix (`M`, `MB` and `MiB` all mean the same here — binary
// units, matching the CLI's `--size`). Returns null when unparseable.
export function parseSize(text) {
  const m = String(text)
    .trim()
    .match(/^(\d+(?:\.\d+)?)\s*([kmgt]?)(?:i?b)?$/i)
  if (!m) return null
  const mult = { '': 1, k: 1024, m: 1024 ** 2, g: 1024 ** 3, t: 1024 ** 4 }[
    m[2].toLowerCase()
  ]
  const n = Math.round(parseFloat(m[1]) * mult)
  return Number.isFinite(n) && n > 0 ? n : null
}

export function download(bytes, filename) {
  const blob = new Blob([bytes], { type: 'application/octet-stream' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 4000)
}
