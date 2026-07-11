// Web Worker: owns the WebAssembly module and the currently-open image so
// heavy inspect/convert work never blocks the UI thread.
//
// The wasm-bindgen `bundler` target initialises the module on import (a
// top-level await handled by vite-plugin-top-level-await), so by the time
// `onmessage` is registered below the wasm is ready — no explicit init gate.
import { probe, supported_targets, Image } from './wasm/fstool.js'

let rawBytes = null // the uploaded file, kept for (re-)open
let img = null // the currently-open Image handle

self.onmessage = (e) => {
  const { id, cmd, args } = e.data
  try {
    let result
    let transfer = []

    switch (cmd) {
      case 'load':
        rawBytes = new Uint8Array(args.buffer)
        img = null
        result = JSON.parse(probe(rawBytes))
        break
      case 'targets':
        result = JSON.parse(supported_targets())
        break
      case 'open':
        if (!rawBytes) throw new Error('no file loaded')
        img = args && args.part
          ? Image.openPartition(rawBytes, args.part)
          : new Image(rawBytes)
        result = { kind: img.kind }
        break
      case 'list':
        if (!img) throw new Error('no image open')
        result = JSON.parse(img.list(args.path))
        break
      case 'read': {
        if (!img) throw new Error('no image open')
        const bytes = img.readFile(args.path)
        result = bytes
        transfer = [bytes.buffer]
        break
      }
      case 'symlink':
        result = img.readSymlink(args.path)
        break
      case 'convert': {
        if (!img) throw new Error('no image open')
        const bytes = img.convert(args.target)
        result = bytes
        transfer = [bytes.buffer]
        break
      }
      default:
        throw new Error('unknown command: ' + cmd)
    }

    self.postMessage({ id, ok: true, result }, transfer)
  } catch (err) {
    self.postMessage({ id, ok: false, error: String((err && err.message) || err) })
  }
}
