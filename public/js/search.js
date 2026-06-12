// Traffic Search modal. Greps captured history for a literal/regex query.
// Search logic lives in the unit-tested search-core.js; this is wiring + render.

import { $, el, statusClass, methodClass } from './util.js';
import { state } from './state.js';
import { searchHistory } from './search-core.js';

function run() {
  const query = $('#srchQuery').value;
  const results = searchHistory(state.history, query, {
    regex: $('#srchRegex').checked,
    caseSensitive: $('#srchCase').checked,
  });
  $('#srchCount').textContent = query ? `— ${results.length} match${results.length === 1 ? '' : 'es'}` : '';

  const tbody = $('#srchTable tbody');
  tbody.innerHTML = '';
  for (const { entry, matchedFields } of results) {
    const status = entry.status ?? entry.response?.status ?? null;
    tbody.appendChild(el('tr', {}, [
      el('td', {}, [el('span', { class: 'method-badge ' + methodClass(entry.method), text: entry.method || '' })]),
      el('td', { text: entry.url || '', title: entry.url || '' }),
      el('td', {}, [
        status == null
          ? el('span', { class: 'muted', text: '–' })
          : el('span', { class: 'code-num ' + statusClass(status), text: String(status) }),
      ]),
      el('td', { text: matchedFields.join(', ') }),
    ]));
  }
}

export function openSearch() {
  $('#srchModal').hidden = false;
  $('#srchQuery').focus();
  run();
}

export function initSearch() {
  $('#srchQuery').addEventListener('input', run);
  $('#srchRegex').addEventListener('change', run);
  $('#srchCase').addEventListener('change', run);
  $('#closeSrch').addEventListener('click', () => ($('#srchModal').hidden = true));
}
