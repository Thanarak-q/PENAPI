// Comparer modal. Diffs two pasted blobs line- or word-by-word. Diff logic
// lives in the unit-tested comparer-core.js; this is wiring + render.

import { $, el } from './util.js';
import { diff } from './comparer-core.js';

function run() {
  const mode = $('#cmpMode').value;
  const result = diff($('#cmpA').value, $('#cmpB').value, mode);
  const host = $('#cmpResult');
  host.hidden = false;
  host.innerHTML = '';

  $('#cmpSummary').textContent = result.identical
    ? 'identical'
    : `+${result.added} added · −${result.removed} removed · ${result.equal} unchanged`;

  if (mode === 'word') {
    const pre = el('pre', { class: 'cmp-pre' });
    for (const op of result.ops) pre.appendChild(el('span', { class: 'cmp-' + op.type, text: op.value }));
    host.appendChild(pre);
    return;
  }
  for (const op of result.ops) {
    const prefix = op.type === 'add' ? '+ ' : op.type === 'del' ? '− ' : '  ';
    host.appendChild(el('div', { class: 'cmp-line cmp-' + op.type, text: prefix + op.value }));
  }
}

export function openComparer() {
  $('#cmpModal').hidden = false;
  $('#cmpA').focus();
}

export function initComparer() {
  $('#cmpRun').addEventListener('click', run);
  $('#cmpMode').addEventListener('change', () => {
    if (!$('#cmpResult').hidden) run();
  });
  $('#closeCmp').addEventListener('click', () => ($('#cmpModal').hidden = true));
}
