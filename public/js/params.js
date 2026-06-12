// Param Analyzer modal. Parsing/classification live in the unit-tested
// params-core.js; this is render + wiring.

import { $, el } from './util.js';
import { analyzeParams } from './params-core.js';

const CAT_LABEL = {
  'open-redirect': 'redirect',
  ssrf: 'ssrf',
  'path-traversal': 'traversal',
  idor: 'idor',
  'auth-secret': 'secret',
  injection: 'injection',
  privilege: 'privilege',
};

function analyze() {
  const host = $('#paOut');
  host.innerHTML = '';
  if (!$('#paIn').value.trim()) {
    host.appendChild(el('p', { class: 'hint', text: 'Paste a URL or query string.' }));
    return;
  }
  const params = analyzeParams($('#paIn').value);
  if (!params.length) {
    host.appendChild(el('p', { class: 'hint', text: 'No query parameters found.' }));
    return;
  }
  for (const p of params) {
    const tags = p.categories.length
      ? p.categories.map((c) => el('span', { class: 'flag-tag flag-vuln', text: CAT_LABEL[c.category] || c.category, title: c.hint }))
      : [el('span', { class: 'flag-tag flag-ok', text: 'no signal' })];
    host.appendChild(el('div', { class: 'pa-row' }, [
      el('div', { class: 'pa-head' }, [
        el('span', { class: 'pa-name', text: p.name }),
        el('span', { class: 'pa-val', text: p.value || '∅', title: p.value }),
      ]),
      el('div', { class: 'pa-tags' }, tags),
      ...p.categories.map((c) => el('div', { class: 'hdr-note', text: '• ' + c.hint })),
    ]));
  }
}

export function openParams() {
  $('#paModal').hidden = false;
  $('#paIn').focus();
}

export function initParams() {
  $('#paRun').addEventListener('click', analyze);
  $('#paIn').addEventListener('input', analyze);
  $('#closePa').addEventListener('click', () => ($('#paModal').hidden = true));
}
