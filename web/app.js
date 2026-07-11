// UI controller. Talks to worker.js (which owns the wasm) over a small
// id-based request/response protocol.

const worker = new Worker('./worker.js', { type: 'module' });
let seq = 0;
const pending = new Map();

worker.onmessage = (e) => {
  const { id, ok, result, error } = e.data;
  const p = pending.get(id);
  if (!p) return;
  pending.delete(id);
  ok ? p.resolve(result) : p.reject(new Error(error));
};

function call(cmd, args, transfer = []) {
  const id = ++seq;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, cmd, args }, transfer);
  });
}

// -- DOM ------------------------------------------------------------------
const $ = (id) => document.getElementById(id);
const drop = $('drop'), fileInput = $('file');
const statusEl = $('status'), statusText = $('status-text');
const errorEl = $('error');
const workspace = $('workspace');
const fileNameEl = $('file-name'), fileSizeEl = $('file-size');
const badgesEl = $('badges'), fsKindEl = $('fs-kind');
const partPicker = $('partition-picker'), partSelect = $('partition-select');
const treeEl = $('tree');
const targetSel = $('target'), convertBtn = $('convert'), convertNote = $('convert-note');

let currentName = 'image';

// -- helpers --------------------------------------------------------------
function humanSize(n) {
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(v < 10 ? 2 : 1)) + ' ' + u[i];
}
function busy(msg) { statusText.textContent = msg; statusEl.hidden = false; }
function idle() { statusEl.hidden = true; }
function showError(e) { errorEl.textContent = String(e.message || e); errorEl.hidden = false; }
function clearError() { errorEl.hidden = true; }
function baseName(name) { return name.replace(/\.(gz|xz|zst|zstd|lz4|lzma|lzo|bz2)$/i, '').replace(/\.[^.]+$/, ''); }

function download(bytes, filename) {
  const blob = new Blob([bytes], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

const KIND_ICON = {
  dir: '📁', file: '📄', symlink: '🔗', char: '⌨', block: '⬛', fifo: '︙', socket: '🔌', unknown: '·',
};

// -- upload flow ----------------------------------------------------------
async function handleFile(file) {
  clearError();
  currentName = file.name || 'image';
  fileNameEl.textContent = currentName;
  fileSizeEl.textContent = humanSize(file.size);
  workspace.hidden = false;
  partPicker.hidden = true;
  treeEl.innerHTML = '';
  badgesEl.innerHTML = '';
  convertNote.textContent = '';
  convertNote.className = 'convert-note';

  try {
    busy('Reading file…');
    const buf = await file.arrayBuffer();
    busy('Probing…');
    const report = await call('load', { buffer: buf }, [buf]);
    renderBadges(report);

    if (report.partition_table) {
      renderPartitions(report.partition_table);
    } else {
      await openImage(null);
    }
  } catch (e) {
    idle();
    showError(e);
  }
}

function renderBadges(report) {
  const badges = [];
  if (report.compression) badges.push({ t: report.compression, accent: false });
  if (report.partition_table) badges.push({ t: report.partition_table.label + ' table', accent: true });
  if (report.filesystem) badges.push({ t: report.filesystem, accent: true });
  badges.push({ t: humanSize(report.content_size), accent: false });
  badgesEl.innerHTML = '';
  for (const b of badges) {
    const s = document.createElement('span');
    s.className = 'badge' + (b.accent ? ' accent' : '');
    s.textContent = b.t;
    badgesEl.appendChild(s);
  }
}

function renderPartitions(table) {
  partSelect.innerHTML = '';
  for (const p of table.partitions) {
    const opt = document.createElement('option');
    opt.value = String(p.index);
    const fs = p.fs ? ` · ${p.fs}` : '';
    const nm = p.name ? ` "${p.name}"` : '';
    opt.textContent = `#${p.index} ${p.kind}${nm} · ${humanSize(p.size)}${fs}`;
    if (!p.fs) opt.disabled = true;
    partSelect.appendChild(opt);
  }
  // Default to the first partition that carries a filesystem.
  const firstFs = table.partitions.find((p) => p.fs);
  if (firstFs) partSelect.value = String(firstFs.index);
  partPicker.hidden = false;
  idle();
}

async function openImage(part) {
  busy('Opening…');
  const { kind } = await call('open', part ? { part } : {});
  fsKindEl.textContent = kind;
  await loadTargets();
  await renderRoot();
  idle();
}

async function loadTargets() {
  if (targetSel.dataset.loaded) return;
  const targets = await call('targets');
  targetSel.innerHTML = '';
  for (const t of targets) {
    const opt = document.createElement('option');
    opt.value = t.id;
    opt.textContent = t.label;
    opt.dataset.ext = t.ext;
    targetSel.appendChild(opt);
  }
  targetSel.dataset.loaded = '1';
}

// -- tree browser ---------------------------------------------------------
function joinPath(dir, name) { return dir === '/' ? '/' + name : dir + '/' + name; }

async function renderRoot() {
  treeEl.innerHTML = '';
  const container = document.createElement('div');
  treeEl.appendChild(container);
  await expandInto(container, '/');
}

async function expandInto(container, path) {
  let entries;
  try {
    entries = await call('list', { path });
  } catch (e) {
    const err = document.createElement('div');
    err.className = 'empty-dir';
    err.textContent = 'cannot read: ' + (e.message || e);
    container.appendChild(err);
    return;
  }
  entries.sort((a, b) => (a.kind === 'dir' ? -1 : 1) - (b.kind === 'dir' ? -1 : 1) || a.name.localeCompare(b.name));
  if (entries.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-dir';
    empty.textContent = '(empty)';
    container.appendChild(empty);
    return;
  }
  for (const entry of entries) {
    container.appendChild(makeRow(entry, path));
  }
}

function makeRow(entry, parentPath) {
  const full = joinPath(parentPath, entry.name);
  const row = document.createElement('div');
  row.className = 'row ' + entry.kind;
  row.setAttribute('role', 'treeitem');

  const twist = document.createElement('span');
  twist.className = 'twist';
  twist.textContent = entry.kind === 'dir' ? '▸' : '';
  row.appendChild(twist);

  const icon = document.createElement('span');
  icon.className = 'icon';
  icon.textContent = KIND_ICON[entry.kind] || '·';
  row.appendChild(icon);

  const name = document.createElement('span');
  name.className = 'rname';
  name.textContent = entry.name;
  row.appendChild(name);

  if (entry.kind === 'file') {
    const dl = document.createElement('span');
    dl.className = 'dl';
    dl.textContent = '⬇ download';
    row.appendChild(dl);
    const size = document.createElement('span');
    size.className = 'rsize';
    size.textContent = humanSize(entry.size);
    row.appendChild(size);
  }

  const wrapper = document.createElement('div');
  wrapper.appendChild(row);

  if (entry.kind === 'dir') {
    let expanded = false, loaded = false;
    const children = document.createElement('div');
    children.className = 'children';
    children.hidden = true;
    wrapper.appendChild(children);
    row.addEventListener('click', async () => {
      expanded = !expanded;
      twist.textContent = expanded ? '▾' : '▸';
      children.hidden = !expanded;
      if (expanded && !loaded) {
        loaded = true;
        await expandInto(children, full);
      }
    });
  } else if (entry.kind === 'file') {
    row.addEventListener('click', async () => {
      try {
        busy('Extracting ' + entry.name + '…');
        const bytes = await call('read', { path: full }, []);
        download(bytes, entry.name);
      } catch (e) {
        showError(e);
      } finally {
        idle();
      }
    });
  }
  return wrapper;
}

// -- convert --------------------------------------------------------------
convertBtn.addEventListener('click', async () => {
  const opt = targetSel.selectedOptions[0];
  if (!opt) return;
  const target = opt.value, ext = opt.dataset.ext || 'out';
  convertNote.className = 'convert-note';
  convertNote.textContent = '';
  convertBtn.disabled = true;
  try {
    busy(`Converting to ${opt.textContent}…`);
    const t0 = performance.now();
    const bytes = await call('convert', { target }, []);
    const dt = ((performance.now() - t0) / 1000).toFixed(1);
    const outName = baseName(currentName) + '.' + ext;
    download(bytes, outName);
    convertNote.className = 'convert-note ok';
    convertNote.textContent = `✓ ${outName} · ${humanSize(bytes.length)} · ${dt}s`;
  } catch (e) {
    convertNote.className = 'convert-note bad';
    convertNote.textContent = '✗ ' + (e.message || e);
  } finally {
    convertBtn.disabled = false;
    idle();
  }
});

$('open-partition').addEventListener('click', async () => {
  clearError();
  const part = parseInt(partSelect.value, 10);
  try {
    await openImage(part);
  } catch (e) { idle(); showError(e); }
});

// -- reset / input wiring -------------------------------------------------
$('reset').addEventListener('click', () => {
  workspace.hidden = true;
  fileInput.value = '';
  clearError();
});
$('pick').addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });
drop.addEventListener('click', () => fileInput.click());
drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') fileInput.click(); });
fileInput.addEventListener('change', () => { if (fileInput.files[0]) handleFile(fileInput.files[0]); });

['dragenter', 'dragover'].forEach((ev) =>
  drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('dragover'); }));
['dragleave', 'drop'].forEach((ev) =>
  drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('dragover'); }));
drop.addEventListener('drop', (e) => {
  const f = e.dataTransfer.files[0];
  if (f) handleFile(f);
});
// Allow dropping a file anywhere on the page too.
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => {
  if (workspace.hidden && e.dataTransfer.files[0]) { e.preventDefault(); handleFile(e.dataTransfer.files[0]); }
});
