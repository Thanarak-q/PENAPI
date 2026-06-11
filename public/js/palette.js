// Command palette (Ctrl/Cmd+K): jump to any endpoint or run an action by typing.

import { $, $$, el, methodClass, goTab } from './util.js';
import { state } from './state.js';
import { loadEndpoint, sendCurrent } from './request.js';
import { sendToFuzzer } from './fuzzer.js';
import { sendToMatrix } from './matrix.js';

let items = [];
let filtered = [];
let cursor = 0;

const ACTIONS = [
  { kind: 'action', label: 'Send current request', hint: 'Ctrl+Enter', run: () => { goTab('request'); sendCurrent(); } },
  { kind: 'action', label: 'Send to Fuzzer', run: () => sendToFuzzer() },
  { kind: 'action', label: 'Send to Access Matrix', run: () => sendToMatrix() },
  { kind: 'action', label: 'Run Quick Attacks', run: () => $('#quickAttackBtn').click() },
  { kind: 'action', label: 'Load Spec…', run: () => $('#loadSpecBtn').click() },
  { kind: 'action', label: 'Import cURL…', run: () => $('#importCurlBtn').click() },
  { kind: 'action', label: 'Open JWT Inspector…', run: () => $('#jwtBtn').click() },
  { kind: 'action', label: 'Manage Identities…', run: () => $('#manageIdentities').click() },
  { kind: 'tab', label: 'Go to: Request', run: () => goTab('request') },
  { kind: 'tab', label: 'Go to: Fuzzer / Brute', run: () => goTab('fuzzer') },
  { kind: 'tab', label: 'Go to: Attack Surface', run: () => goTab('recon') },
  { kind: 'tab', label: 'Go to: Access Matrix', run: () => goTab('matrix') },
  { kind: 'tab', label: 'Go to: Auth Sweep', run: () => goTab('sweep') },
  { kind: 'tab', label: 'Go to: History', run: () => goTab('history') },
];

export function initPalette() {
  $('#paletteInput').addEventListener('input', () => {
    cursor = 0;
    filter();
  });
  $('#paletteInput').addEventListener('keydown', onKey);
  $('#paletteBackdrop').addEventListener('click', (e) => {
    if (e.target.id === 'paletteBackdrop') close();
  });
}

export function openPalette() {
  buildItems();
  $('#paletteInput').value = '';
  cursor = 0;
  filter();
  $('#paletteBackdrop').hidden = false;
  $('#paletteInput').focus();
}

function close() {
  $('#paletteBackdrop').hidden = true;
}

function buildItems() {
  const eps = (state.spec?.endpoints || []).map((ep) => ({
    kind: 'endpoint',
    label: `${ep.method} ${ep.path}`,
    hint: ep.summary || (ep.tags && ep.tags[0]) || '',
    method: ep.method,
    run: () => loadEndpoint(ep),
  }));
  items = [...ACTIONS, ...eps];
}

function filter() {
  const q = $('#paletteInput').value.trim().toLowerCase();
  filtered = !q
    ? items.slice(0, 50)
    : items
        .filter((it) => (it.label + ' ' + (it.hint || '')).toLowerCase().includes(q))
        .slice(0, 80);
  render();
}

function render() {
  const list = $('#paletteList');
  list.innerHTML = '';
  if (!filtered.length) {
    list.appendChild(el('div', { class: 'palette-empty', text: 'No matches' }));
    return;
  }
  filtered.forEach((it, i) => {
    const row = el('div', { class: 'palette-item' + (i === cursor ? ' sel' : ''), onclick: () => choose(i) }, [
      it.kind === 'endpoint'
        ? el('span', { class: 'method-badge ' + methodClass(it.method), text: it.method })
        : el('span', { class: 'palette-kind', text: it.kind === 'tab' ? 'tab' : 'cmd' }),
      el('span', { class: 'palette-label', text: it.kind === 'endpoint' ? it.label.replace(it.method + ' ', '') : it.label }),
      it.hint ? el('span', { class: 'palette-hint', text: it.hint }) : null,
    ]);
    list.appendChild(row);
  });
}

function onKey(e) {
  if (e.key === 'Escape') return close();
  if (e.key === 'ArrowDown') { e.preventDefault(); cursor = Math.min(cursor + 1, filtered.length - 1); render(); scrollSel(); }
  else if (e.key === 'ArrowUp') { e.preventDefault(); cursor = Math.max(cursor - 1, 0); render(); scrollSel(); }
  else if (e.key === 'Enter') { e.preventDefault(); choose(cursor); }
}

function scrollSel() {
  const sel = $('#paletteList .palette-item.sel');
  if (sel) sel.scrollIntoView({ block: 'nearest' });
}

function choose(i) {
  const it = filtered[i];
  if (!it) return;
  close();
  it.run();
}
