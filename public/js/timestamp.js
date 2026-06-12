// Timestamp Converter modal. Parsing/formatting live in the unit-tested
// timestamp-core.js; this is render + wiring.

import { $, el } from './util.js';
import { describeTimestamp, nowStamps } from './timestamp-core.js';

function row(label, value) {
  return el('div', { class: 'ts-row' }, [
    el('span', { class: 'ts-key', text: label }),
    el('span', { class: 'ts-val', text: value }),
  ]);
}

function analyze() {
  const host = $('#tsOut');
  host.innerHTML = '';
  const raw = $('#tsIn').value;
  if (!raw.trim()) {
    host.appendChild(el('p', { class: 'hint', text: 'Enter a Unix epoch (seconds or ms) or an ISO 8601 date.' }));
    return;
  }
  const d = describeTimestamp(raw);
  if (!d) {
    host.appendChild(el('span', { class: 'flag-tag flag-vuln', text: 'unparseable' }));
    return;
  }
  host.appendChild(el('div', { class: 'ts-rel' }, [
    el('span', { class: 'flag-tag ' + (d.isPast ? 'flag-warn' : 'flag-ok'), text: d.relative }),
    el('span', { class: 'hid-meta', text: 'detected as ' + d.detectedAs }),
  ]));
  host.appendChild(row('Unix (s)', String(d.unixSeconds)));
  host.appendChild(row('Unix (ms)', String(d.unixMillis)));
  host.appendChild(row('ISO 8601', d.iso));
  host.appendChild(row('UTC', d.utc));
}

export function openTimestamp() {
  $('#tsModal').hidden = false;
  $('#tsIn').focus();
}

export function initTimestamp() {
  $('#tsRun').addEventListener('click', analyze);
  $('#tsIn').addEventListener('input', analyze);
  $('#tsNow').addEventListener('click', () => {
    $('#tsIn').value = String(nowStamps().unixSeconds);
    analyze();
  });
  $('#closeTs').addEventListener('click', () => ($('#tsModal').hidden = true));
}
