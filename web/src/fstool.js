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
