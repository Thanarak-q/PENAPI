// Site Map modal. Renders the spec's endpoints as a URL-path tree; clicking an
// operation opens it in the Request tab. Tree building lives in the unit-tested
// sitemap-core.js; this is render + wiring.

import { $, el, methodClass, toast } from './util.js';
import { state } from './state.js';
import { buildSiteMap, sortedChildren } from './sitemap-core.js';
import { loadEndpoint } from './request.js';

const INDENT = 14;

function openOp(id) {
  const ep = state.spec?.endpoints.find((e) => e.id === id);
  if (!ep) return;
  loadEndpoint(ep);
  $('#smModal').hidden = true;
}

function opRow(op, path, depth) {
  return el('div', { class: 'sm-op', style: `padding-left:${depth * INDENT}px`, onclick: () => openOp(op.id) }, [
    el('span', { class: 'method-badge ' + methodClass(op.method), text: op.method }),
    el('span', { class: 'sm-op-path', text: path }),
  ]);
}

function renderChildren(node, depth, host) {
  for (const child of sortedChildren(node)) {
    host.appendChild(el('div', { class: 'sm-row', style: `padding-left:${depth * INDENT}px` }, [
      el('span', { class: 'sm-seg', text: '/' + child.segment }),
      el('span', { class: 'sm-count', text: String(child.opCount) }),
    ]));
    for (const op of child.ops) host.appendChild(opRow(op, child.path, depth + 1));
    if (Object.keys(child.children).length) renderChildren(child, depth + 1, host);
  }
}

export function openSiteMap() {
  if (!state.spec) return toast('Load a spec first', true);
  const root = buildSiteMap(state.spec.endpoints);
  const host = $('#smTree');
  host.innerHTML = '';
  for (const op of root.ops) host.appendChild(opRow(op, '/', 0));
  renderChildren(root, 0, host);
  $('#smTitle').textContent = `— ${root.opCount} operations`;
  $('#smModal').hidden = false;
}

export function initSiteMap() {
  $('#closeSm').addEventListener('click', () => ($('#smModal').hidden = true));
}
