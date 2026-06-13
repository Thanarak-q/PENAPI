// Clickjacking PoC modal. Generates a full proof-of-concept HTML page from
// the inputs below. Logic lives in the unit-tested clickjacking-core.js;
// this file is wiring only.
//
// The PoC only works against targets that do NOT set X-Frame-Options or a
// restrictive CSP frame-ancestors directive. Cross-reference the Header
// Auditor (Tools › Recon & analysis › Header Auditor) to check first.

import { $, copy } from './util.js';
import { buildClickjackPoc, defaultOptions } from './clickjacking-core.js';

function render() {
  const html = buildClickjackPoc({
    url:       $('#cjUrl').value,
    decoyText: $('#cjDecoy').value,
    opacity:   Number($('#cjOpacity').value),
    top:       Number($('#cjTop').value),
    left:      Number($('#cjLeft').value),
  });
  $('#cjOut').value = html;
}

function openPreview() {
  const html = $('#cjOut').value;
  const blob = new Blob([html], { type: 'text/html' });
  const blobUrl = URL.createObjectURL(blob);
  window.open(blobUrl, '_blank', 'noopener,noreferrer');
  // Revoke after a short delay so the browser has time to load the page.
  setTimeout(() => URL.revokeObjectURL(blobUrl), 10000);
}

export function openClickjacking() {
  const defaults = defaultOptions();
  // Pre-fill defaults if fields are at their blank initial state.
  if (!$('#cjDecoy').value) $('#cjDecoy').value = defaults.decoyText;
  if (!$('#cjOpacity').value) $('#cjOpacity').value = String(defaults.opacity);
  if (!$('#cjTop').value) $('#cjTop').value = String(defaults.top);
  if (!$('#cjLeft').value) $('#cjLeft').value = String(defaults.left);

  $('#cjModal').hidden = false;
  $('#cjUrl').focus();
  render();
}

export function initClickjacking() {
  // Regenerate whenever any input changes.
  ['#cjUrl', '#cjDecoy', '#cjOpacity', '#cjTop', '#cjLeft'].forEach((sel) => {
    $(sel).addEventListener('input', render);
  });

  $('#cjCopy').addEventListener('click', () => copy($('#cjOut').value));
  $('#cjPreview').addEventListener('click', openPreview);
  $('#closeCj').addEventListener('click', () => ($('#cjModal').hidden = true));
}
