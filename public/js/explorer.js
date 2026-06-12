// Sidebar: endpoint list grouped by tag, with a text find plus a structured
// filter row (method / tag / security / flags) and an inline tag chip editor.

import { $, $$, el, methodClass } from './util.js';
import {
  state, isPinned, togglePin, tagsFor, addEndpointTag, removeEndpointTag,
  allTags, tagUsage, renameTag, deleteTag,
} from './state.js';

let onSelect = () => {};
let collapsed = new Set();

const MUTATING = ['POST', 'PUT', 'PATCH', 'DELETE'];

const filters = {
  methods: new Set(),
  tag: '',
  sec: '',
  body: false,
  idor: false,
  deprecated: false,
  pinned: false,
};

export function initExplorer(selectHandler) {
  onSelect = selectHandler;
  $('#endpointSearch').addEventListener('input', () => render());

  // Datalist for tag autocomplete (created once).
  if (!$('#tagDatalist')) {
    document.body.appendChild(el('datalist', { id: 'tagDatalist' }));
  }

  // Method chips.
  $$('#filterMethods .mchip').forEach((chip) => {
    chip.addEventListener('click', () => {
      const m = chip.dataset.m;
      if (filters.methods.has(m)) filters.methods.delete(m);
      else filters.methods.add(m);
      chip.classList.toggle('on');
      render();
    });
  });
  $('#filterTag')?.addEventListener('change', (e) => { filters.tag = e.target.value; render(); });
  $('#filterSec')?.addEventListener('change', (e) => { filters.sec = e.target.value; render(); });
  $('#flagBody')?.addEventListener('change', (e) => { filters.body = e.target.checked; render(); });
  $('#flagIdor')?.addEventListener('change', (e) => { filters.idor = e.target.checked; render(); });
  $('#flagDeprecated')?.addEventListener('change', (e) => { filters.deprecated = e.target.checked; render(); });
  $('#flagPinned')?.addEventListener('change', (e) => { filters.pinned = e.target.checked; render(); });
  $('#clearFilters')?.addEventListener('click', clearFilters);

  // Tag manager modal.
  $('#closeTags')?.addEventListener('click', () => ($('#tagModal').hidden = true));
}

export function clearFilters() {
  filters.methods.clear();
  filters.tag = '';
  filters.sec = '';
  filters.body = filters.idor = filters.deprecated = filters.pinned = false;
  $$('#filterMethods .mchip').forEach((c) => c.classList.remove('on'));
  ['#flagBody', '#flagIdor', '#flagDeprecated', '#flagPinned'].forEach((s) => { const e = $(s); if (e) e.checked = false; });
  if ($('#filterTag')) $('#filterTag').value = '';
  if ($('#filterSec')) $('#filterSec').value = '';
  render();
}

export function renderExplorer() {
  populateTagFilter();
  render();
}

function activeFilterCount() {
  return (
    filters.methods.size +
    (filters.tag ? 1 : 0) +
    (filters.sec ? 1 : 0) +
    (filters.body ? 1 : 0) +
    (filters.idor ? 1 : 0) +
    (filters.deprecated ? 1 : 0) +
    (filters.pinned ? 1 : 0)
  );
}

function populateTagFilter() {
  const sel = $('#filterTag');
  if (!sel) return;
  const prev = sel.value;
  const specTags = state.spec ? state.spec.tags : [];
  const custom = allTags();
  const opts = ['<option value="">All tags</option>'];
  for (const t of specTags) opts.push(`<option value="${t}">${t}</option>`);
  for (const t of custom) if (!specTags.includes(t)) opts.push(`<option value="${t}">#${t}</option>`);
  sel.innerHTML = opts.join('');
  sel.value = prev;
  if (sel.value !== prev) filters.tag = '';
}

function passesFilters(ep) {
  if (filters.methods.size && !filters.methods.has(ep.method)) return false;
  if (filters.tag) {
    const tags = [...ep.tags, ...tagsFor(ep.id)];
    if (!tags.includes(filters.tag)) return false;
  }
  const hasSec = !!(ep.security && ep.security.length);
  if (filters.sec === 'auth' && !hasSec) return false;
  if (filters.sec === 'unauth' && hasSec) return false;
  if (filters.body && !ep.body) return false;
  if (filters.idor && !(ep.params.path && ep.params.path.length)) return false;
  if (filters.deprecated && !ep.deprecated) return false;
  if (filters.pinned && !isPinned(ep.id)) return false;
  return true;
}

function render() {
  const list = $('#endpointList');
  list.innerHTML = '';
  if (!state.spec) {
    list.appendChild(
      el('div', { class: 'empty-state' }, [
        el('div', { class: 'empty-icon', text: '◇' }),
        el('div', { text: 'No spec loaded' }),
        el('div', { class: 'empty-hint', html: 'Use <b>File → Load Spec</b> to point Swaggernaut at an OpenAPI/Swagger document.' }),
      ])
    );
    $('#endpointCount').textContent = '';
    return;
  }
  const filter = ($('#endpointSearch').value || '').trim().toLowerCase();
  $('#filterBar')?.classList.toggle('has-active', activeFilterCount() > 0);

  const groups = {};
  let shown = 0;
  for (const ep of state.spec.endpoints) {
    if (filter && !matches(ep, filter)) continue;
    if (!passesFilters(ep)) continue;
    const tag = ep.tags[0] || 'default';
    (groups[tag] = groups[tag] || []).push(ep);
    shown++;
  }

  const fc = activeFilterCount();
  $('#endpointCount').textContent =
    `${shown} / ${state.spec.endpoints.length} operations · ${state.spec.tags.length} tags` +
    (fc ? ` · ${fc} filter${fc > 1 ? 's' : ''}` : '');

  const pinnedEps = state.spec.endpoints.filter(
    (ep) => isPinned(ep.id) && (!filter || matches(ep, filter)) && passesFilters(ep)
  );
  if (pinnedEps.length) {
    list.appendChild(
      el('div', { class: 'tag-head pinned-head' }, [
        el('span', { text: '★ PINNED' }),
        el('span', { class: 'count', text: String(pinnedEps.length) }),
      ])
    );
    for (const ep of pinnedEps) list.appendChild(makeRow(ep));
  }

  for (const tag of Object.keys(groups).sort()) {
    const eps = groups[tag];
    const isCollapsed = collapsed.has(tag) && !filter;
    const head = el('div', { class: 'tag-head', onclick: () => toggle(tag) }, [
      el('span', { text: (isCollapsed ? '▸ ' : '▾ ') + tag }),
      el('span', { class: 'count', text: String(eps.length) }),
    ]);
    list.appendChild(head);
    if (isCollapsed) continue;
    for (const ep of eps) list.appendChild(makeRow(ep));
  }
}

// Deterministic color from a tag name (for the focus-tag dot).
function tagColor(tag) {
  let h = 0;
  for (const c of String(tag)) h = (h * 31 + c.charCodeAt(0)) % 360;
  return `hsl(${h} 55% 42%)`;
}

function makeRow(ep) {
  const pinned = isPinned(ep.id);
  const customTags = tagsFor(ep.id);
  const row = el('div', {
    class: 'endpoint' + (state.current && state.current.id === ep.id ? ' active' : ''),
    onclick: () => { onSelect(ep); render(); },
  }, [
    el('span', { class: 'method-badge ' + methodClass(ep.method), text: ep.method }),
    el('div', { class: 'ep-main' }, [
      el('div', { class: 'path', text: ep.path, title: ep.path }),
      ep.summary ? el('div', { class: 'summ', text: ep.summary }) : null,
      customTags.length
        ? el('div', { class: 'endpoint-tags' }, customTags.map((tag) =>
            el('span', {
              class: 'endpoint-tag clickable removable',
              title: 'Click to filter · right-click to remove',
              onclick: (e) => { e.stopPropagation(); filterByTag(tag); },
              oncontextmenu: (e) => {
                e.preventDefault(); e.stopPropagation();
                removeEndpointTag(ep.id, tag);
                render();
              },
            }, [
              el('span', { class: 'tag-color-dot', style: `background:${tagColor(tag)}` }),
              tag,
            ])
          ))
        : null,
    ]),
    el('span', {
      class: 'pin tag-add',
      text: '#',
      title: 'Add focus tag',
      onclick: (e) => { e.stopPropagation(); startTagEdit(ep, row); },
    }),
    el('span', {
      class: 'pin' + (pinned ? ' on' : ''),
      text: pinned ? '★' : '☆',
      title: pinned ? 'Unpin' : 'Pin to top',
      onclick: (e) => { e.stopPropagation(); togglePin(ep.id); render(); },
    }),
  ]);
  return row;
}

// Inline chip editor: reveal a small autocomplete input under the row.
function startTagEdit(ep, row) {
  if (row.querySelector('.tag-edit')) return;
  const dl = $('#tagDatalist');
  if (dl) dl.innerHTML = allTags().map((t) => `<option value="${t}">`).join('');
  const input = el('input', {
    type: 'text', placeholder: 'tag then Enter', list: 'tagDatalist', spellcheck: 'false',
  });
  const editor = el('div', { class: 'tag-edit', onclick: (e) => e.stopPropagation() }, [input]);
  const main = row.querySelector('.ep-main') || row;
  main.appendChild(editor);
  input.focus();
  const commit = () => {
    const raw = input.value.trim();
    if (raw) {
      for (const t of raw.split(/[,\s]+/).filter(Boolean)) addEndpointTag(ep.id, t);
      render();
    } else {
      editor.remove();
    }
  };
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); commit(); }
    else if (e.key === 'Escape') { e.preventDefault(); editor.remove(); }
  });
  input.addEventListener('blur', () => setTimeout(() => editor.remove(), 120));
}

function filterByTag(tag) {
  filters.tag = tag;
  const sel = $('#filterTag');
  if (sel) {
    if (![...sel.options].some((o) => o.value === tag)) populateTagFilter();
    sel.value = tag;
  }
  render();
}

function matches(ep, q) {
  return (
    ep.path.toLowerCase().includes(q) ||
    ep.method.toLowerCase().includes(q) ||
    (ep.summary || '').toLowerCase().includes(q) ||
    (ep.operationId || '').toLowerCase().includes(q) ||
    ep.tags.some((t) => t.toLowerCase().includes(q)) ||
    tagsFor(ep.id).some((t) => t.toLowerCase().includes(q))
  );
}

function toggle(tag) {
  if (collapsed.has(tag)) collapsed.delete(tag);
  else collapsed.add(tag);
  render();
}

// ---- Tag manager modal -------------------------------------------------

export function openTagManager() {
  renderTagManager();
  $('#tagModal').hidden = false;
}

function renderTagManager() {
  const host = $('#tagList');
  host.innerHTML = '';
  const usage = [...tagUsage().entries()].sort((a, b) => a[0].localeCompare(b[0]));
  if (!usage.length) {
    host.appendChild(el('div', { class: 'tag-manager-empty', text: 'No focus tags yet. Add tags to endpoints from the sidebar.' }));
    return;
  }
  for (const [tag, count] of usage) {
    host.appendChild(
      el('div', { class: 'tag-manager-row' }, [
        el('span', { class: 'tag-color-dot', style: `background:${tagColor(tag)}` }),
        el('span', { class: 'tm-name', text: tag }),
        el('span', { class: 'tm-count', text: `${count} endpoint${count > 1 ? 's' : ''}` }),
        el('button', {
          class: 'btn tiny', text: 'Rename', title: 'Rename this focus tag everywhere',
          onclick: () => {
            const next = prompt(`Rename tag "${tag}" to:`, tag);
            if (next && renameTag(tag, next)) { renderTagManager(); renderExplorer(); }
          },
        }),
        el('button', {
          class: 'btn tiny danger', text: 'Delete', title: 'Delete this focus tag from every endpoint',
          onclick: () => {
            if (confirm(`Delete tag "${tag}" from all ${count} endpoint(s)?`)) {
              deleteTag(tag); renderTagManager(); renderExplorer();
            }
          },
        }),
      ])
    );
  }
}
