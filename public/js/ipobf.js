// IP Obfuscator modal. Conversion lives in the unit-tested ipobf-core.js; this
// is render + wiring.

import { $, el, copy, toast } from './util.js';
import { obfuscateRows } from './ipobf-core.js';

function render() {
  const host = $('#ipOut');
  host.innerHTML = '';
  const raw = $('#ipIn').value.trim();
  if (!raw) {
    host.appendChild(el('p', { class: 'hint', text: 'Enter an IPv4 address (e.g. 127.0.0.1).' }));
    return;
  }
  const rows = obfuscateRows(raw);
  if (!rows) {
    host.appendChild(el('span', { class: 'flag-tag flag-vuln', text: 'not a valid IPv4 address' }));
    return;
  }
  for (const [label, value] of rows) {
    const v = el('span', { class: 'ts-val', text: value });
    v.addEventListener('click', () => { copy(value); toast('Copied'); });
    host.appendChild(el('div', { class: 'ts-row' }, [
      el('span', { class: 'ts-key', text: label }),
      v,
    ]));
  }
}

export function openIpObf() {
  $('#ipModal').hidden = false;
  $('#ipIn').focus();
  render();
}

export function initIpObf() {
  $('#ipIn').addEventListener('input', render);
  $('#closeIp').addEventListener('click', () => ($('#ipModal').hidden = true));
}
