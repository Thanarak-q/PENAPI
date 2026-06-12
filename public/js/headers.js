// Security Header Auditor modal. Parsing + audit live in the unit-tested
// headers-core.js; this is render + wiring.

import { $, el } from './util.js';
import { parseHeaders, auditHeaders, summarize } from './headers-core.js';

const LEVEL_CLASS = { missing: 'flag-vuln', weak: 'flag-warn', ok: 'flag-ok' };
const LEVEL_GLYPH = { missing: '✕', weak: '⚠', ok: '✓' };

function analyze() {
  const findings = auditHeaders(parseHeaders($('#hdrIn').value));
  const host = $('#hdrOut');
  host.innerHTML = '';
  if (!$('#hdrIn').value.trim()) {
    host.appendChild(el('p', { class: 'hint', text: 'Paste a raw HTTP response header block.' }));
    return;
  }
  const s = summarize(findings);
  host.appendChild(el('div', { class: 'hdr-summary' }, [
    el('span', { class: 'flag-tag flag-vuln', text: s.missing + ' missing' }),
    el('span', { class: 'flag-tag flag-warn', text: s.weak + ' weak' }),
    el('span', { class: 'flag-tag flag-ok', text: s.ok + ' ok' }),
  ]));
  for (const f of findings) {
    host.appendChild(el('div', { class: 'hdr-row' }, [
      el('span', { class: 'flag-tag ' + LEVEL_CLASS[f.level], text: LEVEL_GLYPH[f.level] + ' ' + f.header }),
      el('span', { class: 'hdr-note', text: f.note }),
    ]));
  }
}

export function openHeaders() {
  $('#hdrModal').hidden = false;
  $('#hdrIn').focus();
}

export function initHeaders() {
  $('#hdrRun').addEventListener('click', analyze);
  $('#hdrIn').addEventListener('input', analyze);
  $('#closeHdr').addEventListener('click', () => ($('#hdrModal').hidden = true));
}
