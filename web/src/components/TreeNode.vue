<script setup>
import { ref, inject } from 'vue'
import { humanSize, joinPath, sortEntries, download } from '../fstool.js'

const props = defineProps({
  entry: { type: Object, required: true }, // { name, kind, size }
  parentPath: { type: String, required: true },
})

const fstool = inject('fstool')
const ui = inject('ui')

const full = joinPath(props.parentPath, props.entry.name)
const isDir = props.entry.kind === 'dir'
const isFile = props.entry.kind === 'file'

const open = ref(false)
const loaded = ref(false)
const children = ref([])
const loadError = ref('')
const downloading = ref(false)

const ICON = {
  dir: '📁', file: '📄', symlink: '🔗', char: '⌨', block: '⬛',
  fifo: '︙', socket: '🔌', unknown: '·',
}

async function toggle() {
  if (!isDir) return
  open.value = !open.value
  if (open.value && !loaded.value) {
    loaded.value = true
    try {
      children.value = sortEntries(await fstool.list(full))
    } catch (e) {
      loadError.value = String(e.message || e)
    }
  }
}

async function extract() {
  if (!isFile || downloading.value) return
  downloading.value = true
  ui.setStatus('Extracting ' + props.entry.name + '…')
  try {
    const bytes = await fstool.read(full)
    download(bytes, props.entry.name)
  } catch (e) {
    ui.setError(e)
  } finally {
    downloading.value = false
    ui.setStatus('')
  }
}
</script>

<template>
  <div class="node">
    <div class="row" :class="entry.kind" @click="isDir ? toggle() : extract()">
      <span class="twist">{{ isDir ? (open ? '▾' : '▸') : '' }}</span>
      <span class="icon">{{ ICON[entry.kind] || '·' }}</span>
      <span class="rname">{{ entry.name }}</span>
      <template v-if="isFile">
        <span class="dl">{{ downloading ? '…' : '⬇ download' }}</span>
        <span class="rsize">{{ humanSize(entry.size) }}</span>
      </template>
    </div>

    <div v-if="isDir && open" class="children">
      <div v-if="loadError" class="empty-dir">cannot read: {{ loadError }}</div>
      <div v-else-if="loaded && !children.length" class="empty-dir">(empty)</div>
      <TreeNode
        v-for="child in children"
        :key="child.name"
        :entry="child"
        :parent-path="full"
      />
    </div>
  </div>
</template>
