// JSON Flattener modal. Flattening lives in the unit-tested jsonflat-core.js;
// this is render + wiring.

import { $, el, copy, toast } from './util.js';
import { flattenJson, sensitiveRows } from './jsonflat-core.js';

let lastRows = [];

function render() {
  const host = $('#jfOut');
  host.innerHTML = '';
  const text = $('#jfIn').value;
  if (!text.trim()) {
    lastRows = [];
    host.appendChild(el('p', { class: 'hint', text: 'Paste a JSON object or array.' }));
    return;
  }
  const { ok, rows, error } = flattenJson(text);
  if (!ok) {
    lastRows = [];
    host.appendChild(el('span', { class: 'flag-tag flag-vuln', text: 'invalid JSON' }));
    host.appendChild(el('div', { class: 'hdr-note', text: error }));
    return;
  }
  lastRows = rows;
  const sens = sensitiveRows(rows);
  host.appendChild(el('div', { class: 'hdr-summary' }, [
    el('span', { class: 'flag-tag flag-ok', text: rows.length + ' leaves' }),
    el('span', { class: 'flag-tag ' + (sens.length ? 'flag-vuln' : 'flag-ok'), text: sens.length + ' sensitive' }),
  ]));
  const showOnlySensitive = $('#jfOnly').checked;
  for (const r of showOnlySensitive ? sens : rows) {
    host.appendChild(el('div', { class: 'jf-row' + (r.sensitive ? ' jf-sensitive' : '') }, [
      el('span', { class: 'jf-path', text: r.path }),
      el('span', { class: 'jf-type', text: r.type }),
      el('span', { class: 'jf-value', text: r.value, title: r.value }),
    ]));
  }
}

export function openJsonFlat() {
  $('#jfModal').hidden = false;
  $('#jfIn').focus();
}

export function initJsonFlat() {
  $('#jfRun').addEventListener('click', render);
  $('#jfIn').addEventListener('input', render);
  $('#jfOnly').addEventListener('change', render);
  $('#jfCopy').addEventListener('click', () => {
    if (!lastRows.length) return toast('Nothing to copy', true);
    copy(lastRows.map((r) => `${r.path} = ${r.value}`).join('\n'));
    toast('Paths copied');
  });
  $('#closeJf').addEventListener('click', () => ($('#jfModal').hidden = true));
}
