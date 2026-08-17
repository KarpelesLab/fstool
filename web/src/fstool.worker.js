// Web Worker: owns the WebAssembly module, the currently-open image, and
// the authoring workspace, so heavy inspect/convert/format work never
// blocks the UI thread.
//
// The wasm-bindgen `bundler` target initialises the module on import (a
// top-level await handled by vite-plugin-top-level-await), so by the time
// `onmessage` is registered below the wasm is ready — no explicit init gate.
import {
  probe,
  supported_targets,
  creatable_filesystems,
  Image,
  Workspace,
} from './wasm/fstool.js'

let rawBytes = null // the uploaded file, kept for (re-)open
let img = null // the currently-open Image handle (inspect mode)
let ws = null // the currently-open Workspace (create/edit mode)

// Every workspace command reports the new layout back, so the UI never has
// to remember to ask — one round trip per action instead of two.
function wsInfo() {
  return JSON.parse(ws.info())
}

function requireWorkspace() {
  if (!ws) throw new Error('no workspace open')
  return ws
}

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

      // -- authoring -----------------------------------------------------

      case 'fsTypes':
        result = JSON.parse(creatable_filesystems())
        break
      case 'newFilesystem':
        img = null
        ws = Workspace.newFilesystem(args.fsType, args.size, args.options || '')
        result = wsInfo()
        break
      case 'newDisk':
        img = null
        ws = Workspace.newDisk(args.size, args.table)
        result = wsInfo()
        break
      case 'editLoaded':
        // Take the file already handed over by `load` into edit mode.
        if (!rawBytes) throw new Error('no file loaded')
        img = null
        ws = Workspace.fromBytes(rawBytes)
        result = wsInfo()
        break
      case 'addPartition':
        result = {
          index: requireWorkspace().addPartition(
            args.size || 0,
            args.kind,
            args.name || '',
            args.fsType || '',
            args.fsOptions || '',
          ),
          info: wsInfo(),
        }
        break
      case 'formatPartition':
        requireWorkspace().formatPartition(
          args.index,
          args.fsType,
          args.fsOptions || '',
        )
        result = wsInfo()
        break
      case 'openPartition':
        requireWorkspace().openPartition(args.index)
        result = wsInfo()
        break
      case 'wsInfo':
        result = wsInfo()
        break
      case 'wsList':
        result = JSON.parse(requireWorkspace().list(args.path))
        break
      case 'wsRead': {
        const bytes = requireWorkspace().readFile(args.path)
        result = bytes
        transfer = [bytes.buffer]
        break
      }
      case 'wsAddFile':
        requireWorkspace().addFile(args.path, new Uint8Array(args.bytes))
        result = { ok: true }
        break
      case 'wsMkdir':
        requireWorkspace().mkdir(args.path)
        result = { ok: true }
        break
      case 'wsRemove':
        requireWorkspace().remove(args.path)
        result = { ok: true }
        break
      case 'wsExport': {
        const bytes = requireWorkspace().export()
        result = bytes
        transfer = [bytes.buffer]
        break
      }
      case 'wsClose':
        ws = null
        result = { ok: true }
        break

      default:
        throw new Error('unknown command: ' + cmd)
    }

    self.postMessage({ id, ok: true, result }, transfer)
  } catch (err) {
    self.postMessage({ id, ok: false, error: String((err && err.message) || err) })
  }
}
