<script setup>
import { ref, reactive, computed, provide } from 'vue'
import { Fstool, humanSize, baseName, download, sortEntries } from './fstool.js'
import TreeNode from './components/TreeNode.vue'
import Builder from './components/Builder.vue'

const fstool = new Fstool()

const phase = ref('empty') // 'empty' | 'loaded' | 'opened'
// 'inspect' is the original drop-a-file flow; 'build' is the authoring pane.
const mode = ref('inspect')
// Set when the user drops a file and picks "Edit" — Builder adopts it.
const adopt = ref(false)
const status = ref('') // non-empty while a blocking op is running
const error = ref('')
const dragover = ref(false)

const file = reactive({ name: '', size: 0 })
const report = ref(null)
const fsKind = ref('')
const targets = ref([])
const selectedTarget = ref('')
const convertNote = reactive({ msg: '', cls: '' })
const converting = ref(false)

const partitionIndex = ref(null)
const rootEntries = ref([])

// Expose worker + helpers to descendant tree nodes.
provide('fstool', fstool)
provide('ui', {
  setStatus: (s) => (status.value = s),
  setError: (e) => (error.value = String(e.message || e)),
})

const badges = computed(() => {
  const r = report.value
  if (!r) return []
  const b = []
  if (r.compression) b.push({ t: r.compression, accent: false })
  if (r.partition_table) b.push({ t: r.partition_table.label + ' table', accent: true })
  if (r.filesystem) b.push({ t: r.filesystem, accent: true })
  b.push({ t: humanSize(r.content_size), accent: false })
  return b
})

const partitions = computed(() => report.value?.partition_table?.partitions ?? [])

async function handleFile(f) {
  error.value = ''
  convertNote.msg = ''
  file.name = f.name || 'image'
  file.size = f.size
  phase.value = 'loaded'
  fsKind.value = ''
  report.value = null
  try {
    status.value = 'Reading file…'
    const buf = await f.arrayBuffer()
    status.value = 'Probing…'
    report.value = await fstool.load(buf)
    if (report.value.partition_table) {
      const firstFs = partitions.value.find((p) => p.fs)
      partitionIndex.value = firstFs ? firstFs.index : null
      status.value = ''
    } else {
      await openImage(null)
    }
  } catch (e) {
    error.value = String(e.message || e)
  } finally {
    if (!report.value?.partition_table) status.value = ''
  }
}

async function openImage(part) {
  error.value = ''
  status.value = 'Opening…'
  try {
    const { kind } = await fstool.open(part)
    fsKind.value = kind
    if (!targets.value.length) targets.value = await fstool.targets()
    if (!selectedTarget.value) selectedTarget.value = targets.value[0]?.id ?? ''
    rootEntries.value = sortEntries(await fstool.list('/'))
    phase.value = 'opened'
  } catch (e) {
    error.value = String(e.message || e)
    phase.value = 'loaded'
  } finally {
    status.value = ''
  }
}

async function runConvert() {
  const target = targets.value.find((t) => t.id === selectedTarget.value)
  if (!target) return
  convertNote.msg = ''
  convertNote.cls = ''
  converting.value = true
  status.value = `Converting to ${target.label}…`
  try {
    const t0 = performance.now()
    const bytes = await fstool.convert(target.id)
    const dt = ((performance.now() - t0) / 1000).toFixed(1)
    const outName = baseName(file.name) + '.' + target.ext
    download(bytes, outName)
    convertNote.cls = 'ok'
    convertNote.msg = `✓ ${outName} · ${humanSize(bytes.length)} · ${dt}s`
  } catch (e) {
    convertNote.cls = 'bad'
    convertNote.msg = '✗ ' + (e.message || e)
  } finally {
    converting.value = false
    status.value = ''
  }
}

function reset() {
  phase.value = 'empty'
  error.value = ''
  report.value = null
}

function startBuilder() {
  adopt.value = false
  mode.value = 'build'
}

// Hand the already-loaded file to the builder instead of the viewer.
function editLoaded() {
  adopt.value = true
  mode.value = 'build'
}

function leaveBuilder() {
  mode.value = 'inspect'
  adopt.value = false
}

// Drag & drop / file input --------------------------------------------------
const fileInput = ref(null)
function onPick() {
  fileInput.value?.click()
}
function onInputChange(e) {
  const f = e.target.files[0]
  if (f) handleFile(f)
}
function onDrop(e) {
  dragover.value = false
  const f = e.dataTransfer.files[0]
  if (f) handleFile(f)
}
</script>

<template>
  <header class="topbar">
    <div class="brand">
      <span class="logo">💾</span>
      <span class="name">fstool</span>
      <span class="tag">web</span>
    </div>
    <nav class="links">
      <a href="https://github.com/KarpelesLab/fstool" target="_blank" rel="noopener">GitHub</a>
      <a href="https://crates.io/crates/fstool" target="_blank" rel="noopener">crates.io</a>
    </nav>
  </header>

  <main
    @dragover.prevent="dragover = true"
    @dragleave.prevent="dragover = false"
    @drop.prevent="onDrop"
  >
    <section class="hero">
      <h1>Build, inspect &amp; convert disk images</h1>
      <p class="sub">
        Create a blank filesystem or a partitioned disk, fill it, and download
        the image — or drop in a <code>tar</code>, <code>zip</code>,
        <code>ext4</code>, <code>squashfs</code>, <code>iso</code> and browse
        what's inside. Everything runs <strong>in your browser</strong>;
        nothing is uploaded.
      </p>
      <div v-if="mode === 'inspect' && phase === 'empty'" class="hero-actions">
        <button class="primary-btn" type="button" @click="startBuilder">
          Create a new image
        </button>
        <span class="or">or drop an existing one below</span>
      </div>
    </section>

    <Builder
      v-if="mode === 'build'"
      :fstool="fstool"
      :adopt="adopt"
      :adopt-name="file.name"
      @close="leaveBuilder"
    />

    <section
      v-if="mode === 'inspect'"
      class="dropzone"
      :class="{ dragover }"
      tabindex="0"
      role="button"
      aria-label="Upload a file"
      @click="onPick"
      @keydown.enter="onPick"
      @keydown.space.prevent="onPick"
    >
      <input ref="fileInput" type="file" hidden @change="onInputChange" />
      <div class="drop-inner">
        <div class="drop-icon">⬆</div>
        <div class="drop-text"><strong>Drop a file here</strong> or click to browse</div>
        <div class="drop-hint">archives &amp; disk images · processed locally</div>
      </div>
    </section>

    <section v-if="mode === 'inspect' && status" class="status">
      <span class="spinner" aria-hidden="true"></span>
      <span>{{ status }}</span>
    </section>

    <section v-if="mode === 'inspect' && error" class="error">{{ error }}</section>

    <section v-if="mode === 'inspect' && phase !== 'empty'" class="workspace">
      <div class="panel meta-panel">
        <div class="file-line">
          <span class="file-name">{{ file.name }}</span>
          <span class="file-size">{{ humanSize(file.size) }}</span>
          <button class="ghost-btn" type="button" @click="editLoaded">Edit</button>
          <button class="ghost-btn" type="button" @click="reset">Clear</button>
        </div>
        <div v-if="badges.length" class="badges">
          <span v-for="(b, i) in badges" :key="i" class="badge" :class="{ accent: b.accent }">
            {{ b.t }}
          </span>
        </div>

        <div v-if="partitions.length" class="partition-picker">
          <label for="partition-select">Partition</label>
          <select id="partition-select" v-model.number="partitionIndex">
            <option
              v-for="p in partitions"
              :key="p.index"
              :value="p.index"
              :disabled="!p.fs"
            >
              #{{ p.index }} {{ p.kind }}<template v-if="p.name"> "{{ p.name }}"</template>
              · {{ humanSize(p.size) }}<template v-if="p.fs"> · {{ p.fs }}</template>
            </option>
          </select>
          <button
            class="ghost-btn"
            type="button"
            :disabled="partitionIndex == null"
            @click="openImage(partitionIndex)"
          >
            Open
          </button>
        </div>
      </div>

      <div v-if="phase === 'opened'" class="columns">
        <div class="panel tree-panel">
          <div class="panel-head">
            <span>Contents</span>
            <span class="pill">{{ fsKind }}</span>
          </div>
          <div class="tree" role="tree">
            <TreeNode
              v-for="entry in rootEntries"
              :key="entry.name"
              :entry="entry"
              parent-path="/"
            />
            <div v-if="!rootEntries.length" class="empty-dir">(empty)</div>
          </div>
        </div>

        <div class="panel convert-panel">
          <div class="panel-head"><span>Convert</span></div>
          <p class="convert-hint">
            Repack the whole image into another format and download the result.
          </p>
          <div class="convert-controls">
            <select v-model="selectedTarget" aria-label="Target format">
              <option v-for="t in targets" :key="t.id" :value="t.id">{{ t.label }}</option>
            </select>
            <button
              class="primary-btn"
              type="button"
              :disabled="converting"
              @click="runConvert"
            >
              Convert &amp; download
            </button>
          </div>
          <div v-if="convertNote.msg" class="convert-note" :class="convertNote.cls">
            {{ convertNote.msg }}
          </div>
        </div>
      </div>
    </section>
  </main>

  <footer class="foot">
    <span>fstool runs as WebAssembly. Your files stay on this device.</span>
  </footer>
</template>
