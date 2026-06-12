// WAF Fingerprint modal. Detection lives in the unit-tested waf-core.js; this
// is render + wiring.

import { $, el } from './util.js';
import { fingerprintRaw } from './waf-core.js';

function analyze() {
  const host = $('#wfOut');
  host.innerHTML = '';
  const headers = $('#wfHeaders').value;
  const body = $('#wfBody').value;
  if (!headers.trim() && !body.trim()) {
    host.appendChild(el('p', { class: 'hint', text: 'Paste response headers (and optionally a body snippet).' }));
    return;
  }
  const hits = fingerprintRaw(headers, body);
  if (!hits.length) {
    host.appendChild(el('span', { class: 'flag-tag flag-ok', text: 'no known WAF/CDN signature matched' }));
    return;
  }
  host.appendChild(el('div', { class: 'hdr-summary' },
    hits.map((name) => el('span', { class: 'flag-tag flag-vuln', text: name }))));
}

export function openWaf() {
  $('#wfModal').hidden = false;
  $('#wfHeaders').focus();
}

export function initWaf() {
  $('#wfRun').addEventListener('click', analyze);
  $('#wfHeaders').addEventListener('input', analyze);
  $('#wfBody').addEventListener('input', analyze);
  $('#closeWf').addEventListener('click', () => ($('#wfModal').hidden = true));
}
