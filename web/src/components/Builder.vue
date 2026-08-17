<script setup>
// Authoring pane: format a blank filesystem or lay out a partitioned disk,
// fill it, and download the image whenever you like.
//
// All state that matters lives in the Rust `Workspace` behind the worker —
// this component only mirrors it. Every mutating call resolves with a fresh
// `info()`, so there is one source of truth and no separate refresh step.
import { ref, reactive, computed, onMounted } from 'vue'
import { humanSize, parseSize, download, sortEntries, joinPath } from '../fstool.js'

const props = defineProps({
  fstool: { type: Object, required: true },
  // Set when the user dropped a file and chose "edit" instead of "inspect".
  adopt: { type: Boolean, default: false },
  adoptName: { type: String, default: '' },
})
const emit = defineEmits(['close'])

const fsTypes = ref([])
const info = ref(null) // WorkspaceInfo from Rust, or null before creation
const busy = ref('')
const error = ref('')

// Creation form ------------------------------------------------------------
const kindChoice = ref('fs') // 'fs' | 'disk'
const form = reactive({ fsType: 'ext4', size: '64MiB', options: '', table: 'gpt' })

// Add-partition form -------------------------------------------------------
const part = reactive({
  size: '',
  rest: true,
  kind: 'linux',
  name: '',
  fsType: 'ext4',
  options: '',
})

// Browser ------------------------------------------------------------------
const cwd = ref('/')
const entries = ref([])
const fileInput = ref(null)

const PARTITION_KINDS = [
  { id: 'linux', label: 'Linux filesystem' },
  { id: 'esp', label: 'EFI System (ESP)' },
  { id: 'msdata', label: 'Microsoft basic data' },
  { id: 'fat32', label: 'FAT32 (MBR 0x0c)' },
  { id: 'swap', label: 'Linux swap' },
  { id: 'bios-boot', label: 'BIOS boot' },
]

const selected = computed(() => fsTypes.value.find((f) => f.id === form.fsType))
const partFsInfo = computed(() => fsTypes.value.find((f) => f.id === part.fsType))
const isDisk = computed(() => !!info.value?.table)
const canEdit = computed(() => !!info.value?.open_fs && info.value.open_editable)
const breadcrumbs = computed(() => {
  const parts = cwd.value.split('/').filter(Boolean)
  let acc = ''
  return parts.map((p) => ({ name: p, path: (acc += '/' + p) }))
})

onMounted(async () => {
  try {
    fsTypes.value = await props.fstool.fsTypes()
    if (props.adopt) await run('Opening image…', () => props.fstool.editLoaded())
  } catch (e) {
    error.value = String(e.message || e)
  }
})

// Run a workspace call that resolves with a fresh WorkspaceInfo.
async function run(label, fn) {
  error.value = ''
  busy.value = label
  try {
    const res = await fn()
    if (res && typeof res === 'object' && 'partitions' in res) info.value = res
    else if (res && res.info) info.value = res.info
    await refreshListing()
    return res
  } catch (e) {
    error.value = String(e.message || e)
    return null
  } finally {
    busy.value = ''
  }
}

async function refreshListing() {
  if (!info.value?.open_fs) {
    entries.value = []
    return
  }
  try {
    entries.value = sortEntries(await props.fstool.wsList(cwd.value))
  } catch (e) {
    // A directory can vanish under us (e.g. after switching partitions);
    // fall back to the root rather than leaving a stale listing on screen.
    if (cwd.value !== '/') {
      cwd.value = '/'
      entries.value = sortEntries(await props.fstool.wsList('/'))
    } else {
      throw e
    }
  }
}

function sizeOr(text, fallback) {
  const n = parseSize(text)
  return n == null ? fallback : n
}

async function createFilesystem() {
  const min = selected.value?.min_size ?? 0
  const size = sizeOr(form.size, selected.value?.default_size ?? 64 << 20)
  if (size < min) {
    error.value = `${selected.value?.label ?? form.fsType} needs at least ${humanSize(min)}`
    return
  }
  cwd.value = '/'
  await run('Formatting…', () =>
    props.fstool.newFilesystem(form.fsType, size, form.options),
  )
}

async function createDisk() {
  const size = sizeOr(form.size, 256 << 20)
  cwd.value = '/'
  await run('Creating disk…', () => props.fstool.newDisk(size, form.table))
}

async function addPartition() {
  cwd.value = '/'
  await run('Adding partition…', () =>
    props.fstool.addPartition({
      size: part.rest ? 0 : sizeOr(part.size, 0),
      kind: part.kind,
      name: part.name,
      fsType: part.fsType,
      fsOptions: part.options,
    }),
  )
}

async function openPartition(index) {
  cwd.value = '/'
  await run(`Opening partition ${index}…`, () => props.fstool.openPartition(index))
}

// Browsing -----------------------------------------------------------------
async function enter(entry) {
  if (entry.kind !== 'dir') return
  cwd.value = joinPath(cwd.value, entry.name)
  await run('Reading…', async () => null)
}
async function goTo(path) {
  cwd.value = path
  await run('Reading…', async () => null)
}
async function goUp() {
  const parts = cwd.value.split('/').filter(Boolean)
  parts.pop()
  await goTo('/' + parts.join('/'))
}

// Editing ------------------------------------------------------------------
function pickFiles() {
  fileInput.value?.click()
}

async function onFilesPicked(e) {
  const files = [...e.target.files]
  e.target.value = ''
  if (!files.length) return
  error.value = ''
  for (const f of files) {
    busy.value = `Adding ${f.name}…`
    try {
      const buf = await f.arrayBuffer()
      await props.fstool.wsAddFile(joinPath(cwd.value, f.name), buf)
    } catch (err) {
      error.value = `${f.name}: ${err.message || err}`
      break
    }
  }
  busy.value = ''
  await run('Refreshing…', () => props.fstool.wsInfo())
}

async function newFolder() {
  const name = prompt('New folder name')
  if (!name) return
  await run('Creating folder…', async () => {
    await props.fstool.wsMkdir(joinPath(cwd.value, name))
    return props.fstool.wsInfo()
  })
}

async function removeEntry(entry) {
  const path = joinPath(cwd.value, entry.name)
  if (!confirm(`Remove ${path}?`)) return
  await run('Removing…', async () => {
    await props.fstool.wsRemove(path)
    return props.fstool.wsInfo()
  })
}

async function downloadEntry(entry) {
  error.value = ''
  busy.value = `Reading ${entry.name}…`
  try {
    const bytes = await props.fstool.wsRead(joinPath(cwd.value, entry.name))
    download(bytes, entry.name)
  } catch (e) {
    error.value = String(e.message || e)
  } finally {
    busy.value = ''
  }
}

const exportNote = reactive({ msg: '', cls: '' })

async function downloadImage() {
  exportNote.msg = ''
  error.value = ''
  busy.value = 'Building image…'
  try {
    const t0 = performance.now()
    const bytes = await props.fstool.wsExport()
    const dt = ((performance.now() - t0) / 1000).toFixed(1)
    const name = isDisk.value
      ? 'disk.img'
      : `image.${info.value?.open_fs === 'iso9660' ? 'iso' : 'img'}`
    download(bytes, name)
    exportNote.cls = 'ok'
    exportNote.msg = `✓ ${name} · ${humanSize(bytes.length)} · ${dt}s`
  } catch (e) {
    exportNote.cls = 'bad'
    exportNote.msg = '✗ ' + (e.message || e)
  } finally {
    busy.value = ''
  }
}

async function startOver() {
  await props.fstool.wsClose()
  info.value = null
  entries.value = []
  cwd.value = '/'
  error.value = ''
  exportNote.msg = ''
}
</script>

<template>
  <section class="workspace">
    <!-- Creation form, shown until a workspace exists -->
    <div v-if="!info" class="panel">
      <div class="panel-head">
        <span>New image</span>
        <button class="ghost-btn" type="button" @click="emit('close')">Cancel</button>
      </div>

      <div class="build-tabs" role="tablist">
        <button
          type="button"
          role="tab"
          :class="{ on: kindChoice === 'fs' }"
          :aria-selected="kindChoice === 'fs'"
          @click="kindChoice = 'fs'"
        >
          Blank filesystem
        </button>
        <button
          type="button"
          role="tab"
          :class="{ on: kindChoice === 'disk' }"
          :aria-selected="kindChoice === 'disk'"
          @click="kindChoice = 'disk'"
        >
          Partitioned disk
        </button>
      </div>

      <div v-if="kindChoice === 'fs'" class="form-grid">
        <label for="b-fs">Filesystem</label>
        <select id="b-fs" v-model="form.fsType">
          <option v-for="f in fsTypes" :key="f.id" :value="f.id">{{ f.label }}</option>
        </select>

        <label for="b-size">Size</label>
        <input id="b-size" v-model="form.size" placeholder="64MiB" />

        <label for="b-opts">Options</label>
        <input
          id="b-opts"
          v-model="form.options"
          :placeholder="selected?.options || 'none'"
        />

        <span></span>
        <p class="form-hint">
          Minimum {{ humanSize(selected?.min_size ?? 0) }}.
          <template v-if="selected?.options">
            Knobs: <code>{{ selected.options }}</code> as <code>key=val,key=val</code>.
          </template>
        </p>

        <span></span>
        <button class="primary-btn" type="button" @click="createFilesystem">
          Create filesystem
        </button>
      </div>

      <div v-else class="form-grid">
        <label for="b-dsize">Disk size</label>
        <input id="b-dsize" v-model="form.size" placeholder="256MiB" />

        <label for="b-table">Partition table</label>
        <select id="b-table" v-model="form.table">
          <option value="gpt">GPT</option>
          <option value="mbr">MBR (max 4 partitions)</option>
        </select>

        <span></span>
        <p class="form-hint">
          Creates an empty table; add partitions next, each with its own
          filesystem.
        </p>

        <span></span>
        <button class="primary-btn" type="button" @click="createDisk">Create disk</button>
      </div>
    </div>

    <!-- The live workspace -->
    <template v-else>
      <div class="panel meta-panel">
        <div class="file-line">
          <span class="file-name">
            {{ isDisk ? info.table.toUpperCase() + ' disk' : 'Bare ' + (info.open_fs || '') }}
          </span>
          <span class="file-size">{{ humanSize(info.size) }}</span>
          <button class="ghost-btn" type="button" @click="startOver">Start over</button>
        </div>
        <div class="badges">
          <span v-if="info.open_fs" class="badge accent">{{ info.open_fs }}</span>
          <span v-if="isDisk" class="badge">
            {{ info.partitions.length }} partition<template v-if="info.partitions.length !== 1">s</template>
          </span>
          <span v-if="isDisk && info.free_bytes" class="badge">
            {{ humanSize(info.free_bytes) }} free
          </span>
          <span v-if="info.open_fs && !info.open_editable" class="badge">read-only</span>
        </div>
      </div>

      <!-- Partition list + add form -->
      <div v-if="isDisk" class="panel">
        <div class="panel-head"><span>Partitions</span></div>
        <table class="part-table">
          <thead>
            <tr><th>#</th><th>Name</th><th>Kind</th><th>Size</th><th>Filesystem</th><th></th></tr>
          </thead>
          <tbody>
            <tr
              v-for="p in info.partitions"
              :key="p.index"
              :class="{ on: p.index === info.open_partition }"
            >
              <td>{{ p.index }}</td>
              <td>{{ p.name || '—' }}</td>
              <td>{{ p.kind }}</td>
              <td>{{ humanSize(p.size) }}</td>
              <td>{{ p.fs || 'unformatted' }}</td>
              <td>
                <button
                  class="ghost-btn"
                  type="button"
                  :disabled="!p.fs || p.index === info.open_partition"
                  @click="openPartition(p.index)"
                >
                  Open
                </button>
              </td>
            </tr>
            <tr v-if="!info.partitions.length">
              <td colspan="6" class="empty-dir">No partitions yet</td>
            </tr>
          </tbody>
        </table>

        <div v-if="info.free_bytes > 0" class="form-grid add-part">
          <label for="p-size">Size</label>
          <div class="row-inline">
            <input
              id="p-size"
              v-model="part.size"
              :disabled="part.rest"
              placeholder="64MiB"
            />
            <label class="check">
              <input v-model="part.rest" type="checkbox" />
              use the rest ({{ humanSize(info.free_bytes) }})
            </label>
          </div>

          <label for="p-kind">Type</label>
          <select id="p-kind" v-model="part.kind">
            <option v-for="k in PARTITION_KINDS" :key="k.id" :value="k.id">
              {{ k.label }}
            </option>
          </select>

          <label for="p-name">Name</label>
          <input id="p-name" v-model="part.name" placeholder="optional" />

          <label for="p-fs">Format as</label>
          <select id="p-fs" v-model="part.fsType">
            <option value="">leave unformatted</option>
            <option v-for="f in fsTypes" :key="f.id" :value="f.id">{{ f.label }}</option>
          </select>

          <label for="p-opts">Options</label>
          <input
            id="p-opts"
            v-model="part.options"
            :placeholder="partFsInfo?.options || 'none'"
          />

          <span></span>
          <button class="primary-btn" type="button" @click="addPartition">
            Add partition
          </button>
        </div>
      </div>

      <!-- File browser -->
      <div v-if="info.open_fs" class="panel">
        <div class="panel-head">
          <span>Contents</span>
          <span class="pill">{{ info.open_fs }}</span>
        </div>

        <div class="crumbs">
          <button class="crumb" type="button" @click="goTo('/')">/</button>
          <template v-for="c in breadcrumbs" :key="c.path">
            <span class="sep">/</span>
            <button class="crumb" type="button" @click="goTo(c.path)">{{ c.name }}</button>
          </template>
          <button
            v-if="cwd !== '/'"
            class="ghost-btn up"
            type="button"
            @click="goUp"
          >
            Up
          </button>
        </div>

        <div class="edit-bar">
          <input ref="fileInput" type="file" multiple hidden @change="onFilesPicked" />
          <button class="primary-btn" type="button" :disabled="!canEdit" @click="pickFiles">
            Add files…
          </button>
          <button class="ghost-btn" type="button" :disabled="!canEdit" @click="newFolder">
            New folder
          </button>
        </div>

        <table class="part-table">
          <tbody>
            <tr v-for="e in entries" :key="e.name">
              <td class="ent-name">
                <button
                  v-if="e.kind === 'dir'"
                  class="crumb"
                  type="button"
                  @click="enter(e)"
                >
                  📁 {{ e.name }}
                </button>
                <span v-else>📄 {{ e.name }}</span>
              </td>
              <td class="ent-size">
                {{ e.kind === 'dir' ? '' : humanSize(e.size) }}
              </td>
              <td class="ent-actions">
                <button
                  v-if="e.kind !== 'dir'"
                  class="ghost-btn"
                  type="button"
                  @click="downloadEntry(e)"
                >
                  Download
                </button>
                <button
                  class="ghost-btn danger"
                  type="button"
                  :disabled="!canEdit"
                  @click="removeEntry(e)"
                >
                  Remove
                </button>
              </td>
            </tr>
            <tr v-if="!entries.length">
              <td colspan="3" class="empty-dir">(empty)</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Download -->
      <div class="panel convert-panel">
        <div class="panel-head"><span>Download</span></div>
        <p class="convert-hint">
          Writes out the image as it stands right now. You can keep editing
          afterwards and download again.
        </p>
        <div class="convert-controls">
          <button class="primary-btn" type="button" @click="downloadImage">
            Download image ({{ humanSize(info.size) }})
          </button>
        </div>
        <div v-if="exportNote.msg" class="convert-note" :class="exportNote.cls">
          {{ exportNote.msg }}
        </div>
      </div>
    </template>

    <section v-if="busy" class="status">
      <span class="spinner" aria-hidden="true"></span>
      <span>{{ busy }}</span>
    </section>
    <section v-if="error" class="error">{{ error }}</section>
  </section>
</template>
