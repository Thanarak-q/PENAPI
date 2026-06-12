// HTTP Status Reference modal. The table + search live in the unit-tested
// status-core.js; this is render + wiring.

import { $, el } from './util.js';
import { searchStatuses } from './status-core.js';

function classFor(code) {
  if (code >= 500) return 'st-5xx';
  if (code >= 400) return 'st-4xx';
  if (code >= 300) return 'st-3xx';
  return 'st-2xx';
}

function render() {
  const host = $('#stOut');
  host.innerHTML = '';
  const rows = searchStatuses($('#stIn').value);
  if (!rows.length) {
    host.appendChild(el('p', { class: 'hint', text: 'No status code matches.' }));
    return;
  }
  for (const e of rows) {
    host.appendChild(el('div', { class: 'st-row' }, [
      el('span', { class: 'st-code ' + classFor(e.code), text: String(e.code) }),
      el('div', { class: 'st-body' }, [
        el('div', { class: 'st-phrase', text: e.phrase }),
        el('div', { class: 'hdr-note', text: e.note }),
      ]),
    ]));
  }
}

export function openStatus() {
  $('#stModal').hidden = false;
  $('#stIn').focus();
  render();
}

export function initStatus() {
  $('#stIn').addEventListener('input', render);
  $('#closeSt').addEventListener('click', () => ($('#stModal').hidden = true));
}
