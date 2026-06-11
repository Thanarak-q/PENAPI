// Sidebar: endpoint list grouped by tag, with filtering.

import { $, el, methodClass } from './util.js';
import { state, isPinned, togglePin, tagsFor, addEndpointTag, removeEndpointTag } from './state.js';

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
  if (!state.spec) {
    list.appendChild(
      el('div', { class: 'empty-state' }, [
        el('div', { class: 'empty-icon', text: '◇' }),
        el('div', { text: 'No spec loaded' }),
        el('div', { class: 'empty-hint', html: 'Click <b>Load Spec</b> above to point PenAPI at an OpenAPI/Swagger document.' }),
      ])
    );
    $('#endpointCount').textContent = '';
    return;
  }
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

  // Pinned group at the top (respects the active filter).
  const pinnedEps = state.spec.endpoints.filter(
    (ep) => isPinned(ep.id) && (!q || matches(ep, q))
  );
  if (pinnedEps.length) {
    list.appendChild(
      el('div', { class: 'tag-head pinned-head' }, [
        el('span', { text: '★ PINNED' }),
        el('span', { class: 'count', text: String(pinnedEps.length) }),
      ])
    );
    for (const ep of pinnedEps) list.appendChild(makeRow(ep, filter));
  }

  for (const tag of Object.keys(groups).sort()) {
    const eps = groups[tag];
    const isCollapsed = collapsed.has(tag) && !q;
    const head = el('div', { class: 'tag-head', onclick: () => toggle(tag, filter) }, [
      el('span', { text: (isCollapsed ? '▸ ' : '▾ ') + tag }),
      el('span', { class: 'count', text: String(eps.length) }),
    ]);
    list.appendChild(head);
    if (isCollapsed) continue;
    for (const ep of eps) list.appendChild(makeRow(ep, filter));
  }
}

function makeRow(ep, filter) {
  const pinned = isPinned(ep.id);
  const customTags = tagsFor(ep.id);
  return el('div', {
    class: 'endpoint' + (state.current && state.current.id === ep.id ? ' active' : ''),
    onclick: () => {
      onSelect(ep);
      render(filter);
    },
  }, [
    el('span', { class: 'method-badge ' + methodClass(ep.method), text: ep.method }),
    el('div', { style: 'overflow:hidden;flex:1' }, [
      el('div', { class: 'path', text: ep.path, title: ep.path }),
      ep.summary ? el('div', { class: 'summ', text: ep.summary }) : null,
      customTags.length
        ? el('div', { class: 'endpoint-tags' }, customTags.map((tag) =>
            el('span', {
              class: 'endpoint-tag removable',
              text: tag,
              title: 'Remove tag',
              onclick: (e) => {
                e.stopPropagation();
                removeEndpointTag(ep.id, tag);
                renderCurrentTags(ep);
                render(filter);
              },
            })
          ))
        : null,
    ]),
    el('span', {
      class: 'pin tag-add',
      text: '#',
      title: 'Add focus tag',
      onclick: (e) => {
        e.stopPropagation();
        const tags = prompt('Tags for this endpoint (comma, space, or newline separated)');
        if (!tags) return;
        for (const tag of tags.split(/[,\s]+/).filter(Boolean)) {
          addEndpointTag(ep.id, tag);
        }
        renderCurrentTags(ep);
        render(filter);
      },
    }),
    el('span', {
      class: 'pin' + (pinned ? ' on' : ''),
      text: pinned ? '★' : '☆',
      title: pinned ? 'Unpin' : 'Pin to top',
      onclick: (e) => {
        e.stopPropagation();
        togglePin(ep.id);
        render(filter);
      },
    }),
  ]);
}

function renderCurrentTags(ep) {
  if (!state.current || state.current.id !== ep.id) return;
  const host = $('#currentTags');
  if (!host) return;
  host.innerHTML = '';
  for (const tag of [...ep.tags, ...tagsFor(ep.id)]) {
    host.appendChild(el('span', { class: 'endpoint-tag', text: tag }));
  }
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

function toggle(tag, filter) {
  if (collapsed.has(tag)) collapsed.delete(tag);
  else collapsed.add(tag);
  render(filter);
}
