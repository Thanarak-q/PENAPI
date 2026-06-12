// Timing Analysis modal. Aggregates per-endpoint response times from history.
// Aggregation lives in the unit-tested timing-core.js; this is render + wiring.

import { $, el, methodClass } from './util.js';
import { state } from './state.js';
import { aggregateTimings } from './timing-core.js';

function bar(value, max) {
  return el('span', { class: 'tm-bar', style: `width:${Math.max(2, Math.round((value / max) * 60))}px` });
}

function render() {
  const rows = aggregateTimings(state.history);
  const tbody = $('#tmTable tbody');
  tbody.innerHTML = '';
  $('#tmCount').textContent = rows.length ? `— ${rows.length} endpoint${rows.length === 1 ? '' : 's'}` : '';

  if (!rows.length) {
    tbody.appendChild(el('tr', {}, [
      el('td', { class: 'muted', colspan: '6', text: 'No timed requests yet — send some, then reopen.' }),
    ]));
    return;
  }
  const maxAvg = Math.max(...rows.map((r) => r.avg), 1);
  for (const r of rows) {
    tbody.appendChild(el('tr', {}, [
      el('td', {}, [el('span', { class: 'method-badge ' + methodClass(r.method), text: r.method })]),
      el('td', { text: r.url, title: r.url }),
      el('td', { text: String(r.count) }),
      el('td', { text: Math.round(r.min) + 'ms' }),
      el('td', {}, [el('span', { class: 'tm-avg', text: Math.round(r.avg) + 'ms' }), bar(r.avg, maxAvg)]),
      el('td', { text: Math.round(r.max) + 'ms' }),
    ]));
  }
}

export function openTiming() {
  render();
  $('#tmModal').hidden = false;
}

export function initTiming() {
  $('#closeTm').addEventListener('click', () => ($('#tmModal').hidden = true));
}
