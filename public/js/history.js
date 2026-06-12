// History tab: list of every sent request, replayable.

import { $, el, statusClass, methodClass, goTab, headersToText, prettyJson } from './util.js';
import { state, save } from './state.js';
import { renderResponse } from './request.js';
import { sendProxy } from './api.js';

let selected = null;

export function initHistory() {
  $('#clearHistory').addEventListener('click', () => {
    state.history = [];
    save();
    renderHistory();
  });
  $('#closeHistoryDetail').addEventListener('click', () => ($('#historyDetailModal').hidden = true));
  $('#historyReplay').addEventListener('click', async () => {
    if (!selected) return;
    $('#historyDetailModal').hidden = true;
    await replay(selected);
  });
}

export function renderHistory() {
  const tbody = $('#historyTable tbody');
  tbody.innerHTML = '';
  $('#historyCount').textContent = `${state.history.length} requests`;
  for (const h of state.history) {
    const tr = el('tr', { onclick: () => showDetail(h) }, [
      el('td', { text: new Date(h.at).toLocaleTimeString() }),
      el('td', {}, [el('span', { class: 'method-badge ' + methodClass(h.method), text: h.method })]),
      el('td', { text: h.url, title: h.url }),
      el('td', {}, [
        h.error
          ? el('span', { text: 'ERR', style: 'color:var(--red)' })
          : el('span', { class: 'code-num ' + statusClass(h.status), text: String(h.status) }),
      ]),
      el('td', { text: h.size == null ? '–' : String(h.size) }),
      el('td', { text: h.timeMs == null ? '–' : String(h.timeMs) }),
      el('td', {}, [
        el('button', {
          class: 'btn tiny',
          text: 'View',
          title: 'Open request and response details',
          onclick: (e) => {
            e.stopPropagation();
            showDetail(h);
          },
        }),
        el('span', {
          class: 'del',
          text: '↻',
          title: 'replay',
          onclick: (e) => {
            e.stopPropagation();
            replay(h);
          },
        }),
      ]),
    ]);
    tbody.appendChild(tr);
  }
}

function showDetail(h) {
  selected = h;
  $('#historyDetailTitle').textContent = `— ${h.method} ${h.status || 'ERR'}`;
  $('#historyReq').textContent = formatRequest(h);
  $('#historyRes').textContent = formatResponse(h);
  $('#historyDetailModal').hidden = false;
}

function formatRequest(h) {
  const req = h.request || {};
  return [
    `${req.method || h.method || 'GET'} ${req.url || h.url || ''}`,
    '',
    headersToText(req.headers || {}),
    req.body ? `\n\n${tryPretty(req.body)}` : '',
  ].join('\n').trim();
}

function formatResponse(h) {
  const res = h.response || {};
  if (!res && h.error) return h.error;
  return [
    res.error ? `ERR ${res.error}` : `HTTP ${res.status || h.status || ''} ${res.statusText || ''}`.trim(),
    res.timeMs != null ? `${res.timeMs} ms · ${res.size ?? '-'} bytes${res.truncated ? ' · truncated' : ''}` : '',
    res.finalUrl ? `Final URL: ${res.finalUrl}` : '',
    '',
    headersToText(res.headers || {}),
    res.body ? `\n\n${tryPretty(res.body)}` : '',
  ].filter((x) => x != null).join('\n').trim();
}

function tryPretty(text) {
  return prettyJson(String(text));
}

async function replay(h) {
  if (!h.request) return;
  const { result } = await sendProxy({ ...h.request, followRedirects: false });
  renderResponse(result);
  goTab('request');
}
