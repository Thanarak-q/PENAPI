// History tab: list of every sent request, replayable.

import { $, $$, el, statusClass, methodClass } from './util.js';
import { state, save } from './state.js';
import { renderResponse } from './request.js';
import { sendProxy } from './api.js';

export function initHistory() {
  $('#clearHistory').addEventListener('click', () => {
    state.history = [];
    save();
    renderHistory();
  });
}

export function renderHistory() {
  const tbody = $('#historyTable tbody');
  tbody.innerHTML = '';
  $('#historyCount').textContent = `${state.history.length} requests`;
  for (const h of state.history) {
    const tr = el('tr', {}, [
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
        el('span', { class: 'del', text: '↻', title: 'replay', onclick: () => replay(h) }),
      ]),
    ]);
    tbody.appendChild(tr);
  }
}

async function replay(h) {
  if (!h.request) return;
  const { result } = await sendProxy({ ...h.request, followRedirects: false });
  renderResponse(result);
  $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === 'request'));
  $$('.panel').forEach((p) => p.classList.toggle('active', p.dataset.panel === 'request'));
}
