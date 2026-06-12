// Attack Headers modal. The library + search live in the unit-tested
// attackhdr-core.js; this is render + wiring.

import { $, el, copy, toast } from './util.js';
import { searchHeaders, toHeaderLine } from './attackhdr-core.js';

function render() {
  const host = $('#ahOut');
  host.innerHTML = '';
  const rows = searchHeaders($('#ahIn').value);
  if (!rows.length) {
    host.appendChild(el('p', { class: 'hint', text: 'No header matches.' }));
    return;
  }
  let lastCat = null;
  for (const e of rows) {
    if (e.category !== lastCat) {
      host.appendChild(el('div', { class: 'rd-group-title', text: e.category }));
      lastCat = e.category;
    }
    const btn = el('button', { class: 'btn tiny ghost', text: 'copy' });
    btn.addEventListener('click', () => { copy(toHeaderLine(e)); toast('Header copied'); });
    host.appendChild(el('div', { class: 'ah-row' }, [
      el('div', { class: 'ah-head' }, [
        el('span', { class: 'ah-name', text: e.name }),
        el('span', { class: 'ah-sample', text: e.sample }),
        btn,
      ]),
      el('div', { class: 'hdr-note', text: e.note }),
    ]));
  }
}

export function openAttackHdr() {
  $('#ahModal').hidden = false;
  $('#ahIn').focus();
  render();
}

export function initAttackHdr() {
  $('#ahIn').addEventListener('input', render);
  $('#closeAh').addEventListener('click', () => ($('#ahModal').hidden = true));
}
