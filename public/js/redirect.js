// Redirect & SSRF Payloads modal. Generation lives in the unit-tested
// redirect-core.js; this is render + wiring. Generation only — nothing is sent.

import { $, el, copy, toast } from './util.js';
import { allPayloads } from './redirect-core.js';

function lines() {
  const groups = allPayloads($('#rdAttacker').value, $('#rdTarget').value);
  const out = [];
  for (const [name, payloads] of Object.entries(groups)) {
    out.push('# ' + name);
    out.push(...payloads);
    out.push('');
  }
  return out.join('\n').trimEnd();
}

function render() {
  const host = $('#rdOut');
  host.innerHTML = '';
  const groups = allPayloads($('#rdAttacker').value, $('#rdTarget').value);
  for (const [name, payloads] of Object.entries(groups)) {
    host.appendChild(el('div', { class: 'rd-group-title', text: name }));
    for (const p of payloads) {
      host.appendChild(el('div', { class: 'ts-row' }, [
        el('span', { class: 'ts-val', text: p }),
      ]));
    }
  }
}

export function openRedirect() {
  $('#rdModal').hidden = false;
  render();
  $('#rdAttacker').focus();
}

export function initRedirect() {
  $('#rdAttacker').addEventListener('input', render);
  $('#rdTarget').addEventListener('input', render);
  $('#rdCopy').addEventListener('click', () => {
    copy(lines());
    toast('Payloads copied');
  });
  $('#closeRd').addEventListener('click', () => ($('#rdModal').hidden = true));
}
