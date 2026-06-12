// Injection Payloads modal. The library lives in the unit-tested
// payloads-lib-core.js; this is render + wiring. Generation only — nothing
// is sent.

import { $, el, copy, toast } from './util.js';
import { allPayloads } from './payloads-lib-core.js';

function currentMarker() {
  return $('#plMarker').value.trim() || '{{M}}';
}

function render() {
  const host = $('#plOut');
  host.innerHTML = '';
  const groups = allPayloads(currentMarker());
  for (const [cat, list] of Object.entries(groups)) {
    host.appendChild(el('div', { class: 'rd-group-title', text: cat }));
    for (const p of list) {
      const btn = el('button', { class: 'btn tiny ghost', text: 'copy' });
      btn.addEventListener('click', () => { copy(p); toast('Copied'); });
      host.appendChild(el('div', { class: 'pl-row' }, [
        el('span', { class: 'pl-payload', text: p }),
        btn,
      ]));
    }
  }
}

export function openPayloadLib() {
  $('#plModal').hidden = false;
  render();
}

export function initPayloadLib() {
  $('#plMarker').addEventListener('input', render);
  $('#closePl').addEventListener('click', () => ($('#plModal').hidden = true));
}
