// Hash Identifier modal. Identification logic lives in the unit-tested
// hashid-core.js; this is render + wiring.

import { $, el } from './util.js';
import { identifyHash } from './hashid-core.js';

function analyze() {
  const r = identifyHash($('#hidIn').value);
  const host = $('#hidOut');
  host.innerHTML = '';
  if (!r.input) {
    host.appendChild(el('p', { class: 'hint', text: 'Paste a hash to identify likely algorithms.' }));
    return;
  }
  host.appendChild(el('div', { class: 'hid-meta', text: `${r.length} chars` }));
  if (r.candidates.length) {
    host.appendChild(el('div', { class: 'hid-cands' },
      r.candidates.map((c) => el('span', { class: 'flag-tag flag-ok', text: c }))));
  } else {
    host.appendChild(el('div', { class: 'hid-cands' }, [
      el('span', { class: 'flag-tag flag-warn', text: 'no confident match' }),
    ]));
  }
  for (const n of r.notes) {
    host.appendChild(el('div', { class: 'hdr-note', text: '• ' + n }));
  }
}

export function openHashId() {
  $('#hidModal').hidden = false;
  $('#hidIn').focus();
}

export function initHashId() {
  $('#hidRun').addEventListener('click', analyze);
  $('#hidIn').addEventListener('input', analyze);
  $('#closeHid').addEventListener('click', () => ($('#hidModal').hidden = true));
}
