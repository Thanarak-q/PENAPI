// Sidebar: endpoint list grouped by tag, with filtering.

import { $, el, methodClass } from './util.js';
import { state } from './state.js';

let onSelect = () => {};
let collapsed = new Set();

export function initExplorer(selectHandler) {
  onSelect = selectHandler;
  $('#endpointSearch').addEventListener('input', (e) => render(e.target.value));
}

export function renderExplorer() {
  render($('#endpointSearch').value || '');
}

function render(filter) {
  const list = $('#endpointList');
  list.innerHTML = '';
  if (!state.spec) return;
  const q = filter.trim().toLowerCase();

  const groups = {};
  let shown = 0;
  for (const ep of state.spec.endpoints) {
    if (q && !matches(ep, q)) continue;
    const tag = ep.tags[0] || 'default';
    (groups[tag] = groups[tag] || []).push(ep);
    shown++;
  }

  $('#endpointCount').textContent =
    `${shown} / ${state.spec.endpoints.length} operations · ${state.spec.tags.length} tags`;

  for (const tag of Object.keys(groups).sort()) {
    const eps = groups[tag];
    const isCollapsed = collapsed.has(tag) && !q;
    const head = el('div', { class: 'tag-head', onclick: () => toggle(tag, filter) }, [
      el('span', { text: (isCollapsed ? '▸ ' : '▾ ') + tag }),
      el('span', { class: 'count', text: String(eps.length) }),
    ]);
    list.appendChild(head);
    if (isCollapsed) continue;
    for (const ep of eps) {
      const row = el('div', {
        class: 'endpoint' + (state.current && state.current.id === ep.id ? ' active' : ''),
        onclick: () => onSelect(ep),
      }, [
        el('span', { class: 'method-badge ' + methodClass(ep.method), text: ep.method }),
        el('div', { style: 'overflow:hidden' }, [
          el('div', { class: 'path', text: ep.path, title: ep.path }),
          ep.summary ? el('div', { class: 'summ', text: ep.summary }) : null,
        ]),
      ]);
      list.appendChild(row);
    }
  }
}

function matches(ep, q) {
  return (
    ep.path.toLowerCase().includes(q) ||
    ep.method.toLowerCase().includes(q) ||
    (ep.summary || '').toLowerCase().includes(q) ||
    (ep.operationId || '').toLowerCase().includes(q) ||
    ep.tags.some((t) => t.toLowerCase().includes(q))
  );
}

function toggle(tag, filter) {
  if (collapsed.has(tag)) collapsed.delete(tag);
  else collapsed.add(tag);
  render(filter);
}
