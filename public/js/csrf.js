// CSRF PoC modal. Generates a self-submitting HTML page from the current
// request. Logic lives in the unit-tested csrf-core.js; this is wiring only.

import { $, copy, toast } from './util.js';
import { getCurrentRequest } from './request.js';
import { buildCsrfPoc } from './csrf-core.js';

function open() {
  const req = getCurrentRequest({ withIdentity: true });
  if (!req.url) return toast('No request loaded', true);

  const { html, notes } = buildCsrfPoc(req);
  $('#csrfOut').value = html;

  const host = $('#csrfNotes');
  host.innerHTML = '';
  for (const note of notes) {
    const div = document.createElement('div');
    div.className = 'csrf-note';
    div.textContent = '⚠ ' + note;
    host.appendChild(div);
  }
  $('#csrfModal').hidden = false;
}

function download() {
  const blob = new Blob([$('#csrfOut').value], { type: 'text/html' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'csrf-poc.html';
  a.click();
  URL.revokeObjectURL(url);
}

export function initCsrf() {
  $('#csrfBtn').addEventListener('click', open);
  $('#closeCsrf').addEventListener('click', () => ($('#csrfModal').hidden = true));
  $('#csrfCopy').addEventListener('click', () => copy($('#csrfOut').value));
  $('#csrfDownload').addEventListener('click', download);
}
