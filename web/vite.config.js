import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import wasm from 'vite-plugin-wasm'
import topLevelAwait from 'vite-plugin-top-level-await'

// Project site served from https://<user>.github.io/fstool/, so assets must
// be referenced under /fstool/. Override with BASE_PATH for other hosts.
const base = process.env.BASE_PATH ?? '/fstool/'

export default defineConfig({
  base,
  plugins: [vue(), wasm(), topLevelAwait()],
  // The wasm-bindgen module is imported inside the Web Worker; the same
  // plugins must run on the worker bundle.
  worker: {
    format: 'es',
    plugins: () => [wasm(), topLevelAwait()],
  },
  build: {
    target: 'es2022',
    chunkSizeWarningLimit: 4096, // the wasm-glue chunk is large by nature
  },
})
