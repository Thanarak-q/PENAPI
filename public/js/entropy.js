// Entropy Analyzer modal. Measurement lives in the unit-tested entropy-core.js;
// this is render + wiring.

import { $, el } from './util.js';
import { analyzeEntropy } from './entropy-core.js';

const LEVEL_CLASS = { empty: 'flag-ok', weak: 'flag-vuln', fair: 'flag-warn', good: 'flag-ok', strong: 'flag-ok' };

function row(label, value) {
  return el('div', { class: 'ts-row' }, [
    el('span', { class: 'ts-key', text: label }),
    el('span', { class: 'ts-val', text: value }),
  ]);
}

function analyze() {
  const host = $('#enOut');
  host.innerHTML = '';
  const v = $('#enIn').value;
  if (!v) {
    host.appendChild(el('p', { class: 'hint', text: 'Paste a token, key, or session ID to measure its randomness.' }));
    return;
  }
  const r = analyzeEntropy(v);
  const cls = Object.entries(r.classes).filter(([, on]) => on).map(([k]) => k).join(', ') || '—';
  host.appendChild(el('div', { class: 'ts-rel' }, [
    el('span', { class: 'flag-tag ' + (LEVEL_CLASS[r.verdict.level] || 'flag-ok'), text: r.verdict.label }),
  ]));
  host.appendChild(row('Length', String(r.length)));
  host.appendChild(row('Unique', String(r.unique)));
  host.appendChild(row('Bits/char', String(r.bitsPerChar)));
  host.appendChild(row('Shannon', r.bitsTotal + ' bits'));
  host.appendChild(row('Keyspace', '~' + r.keyspaceBits + ' bits (alphabet ' + r.alphabet + ')'));
  host.appendChild(row('Charset', cls));
}

export function openEntropy() {
  $('#enModal').hidden = false;
  $('#enIn').focus();
}

export function initEntropy() {
  $('#enRun').addEventListener('click', analyze);
  $('#enIn').addEventListener('input', analyze);
  $('#closeEn').addEventListener('click', () => ($('#enModal').hidden = true));
}
