// Access Matrix tab: replay one request as every identity to find broken
// object/function-level authorization.

import { $, $$, el, statusClass, toast } from './util.js';
import { state } from './state.js';
import { textToHeaders } from './util.js';
import { getCurrentRequest } from './request.js';
import { runMatrix } from './api.js';
import { attachExport } from './export.js';
import { goTab } from './util.js';

let lastResults = [];

// Load the current request into the matrix and switch to it (cross-tab UX).
export function sendToMatrix() {
  const req = getCurrentRequest({ withIdentity: false });
  $('#matrixMethod').value = req.method;
  $('#matrixUrl').value = req.url;
  goTab('matrix');
}

export function initMatrix() {
  $('#matrixLoad').addEventListener('click', () => {
    const req = getCurrentRequest({ withIdentity: false });
    $('#matrixMethod').value = req.method;
    $('#matrixUrl').value = req.url;
  });
  $('#matrixRun').addEventListener('click', run);
  $('#matrixFilter').addEventListener('input', () => renderMatrix(lastResults));

  attachExport(document.querySelector('[data-panel="matrix"] .matrix-head'), () => ({
    name: 'penapi-matrix',
    headers: ['identity', 'status', 'size', 'timeMs', 'error'],
    rows: lastResults,
  }));
}

async function run() {
  const url = $('#matrixUrl').value.trim();
  if (!url) return toast('No URL — load a request first', true);
  const baseReq = getCurrentRequest({ withIdentity: false });
  const request = {
    method: $('#matrixMethod').value,
    url,
    headers: baseReq.headers,
    body: baseReq.body,
  };
  const writeMethod = !['GET', 'HEAD', 'OPTIONS'].includes((request.method || 'GET').toUpperCase());

  const identities = state.identities.map((i) => {
    const parsed = textToHeaders(i.headers);
    const headers = {};
    for (const [k, v] of Object.entries(parsed)) headers[k] = v === 'null' ? null : v;
    return { name: i.name, headers };
  });
  if (!identities.length) return toast('No identities defined', true);
  if (writeMethod) {
    const warning = [
      `Access Matrix will replay this ${request.method} request as ${identities.length} identities.`,
      'That may modify data multiple times.',
      'Continue?',
    ].join('\n');
    if (!confirm(warning)) return;
  }

  $('#matrixRun').disabled = true;
  $('#matrixTable tbody').innerHTML = '<tr><td colspan="6" class="muted">running…</td></tr>';
  const { ok, results, error } = await runMatrix(request, identities);
  $('#matrixRun').disabled = false;
  if (!ok) return toast('Matrix error: ' + error, true);

  lastResults = results;
  renderMatrix(results);
}

const LOW_PRIV = /unauth|guest|anon|user|public|none|other/i;

function renderMatrix(results) {
  const tbody = $('#matrixTable tbody');
  tbody.innerHTML = '';
  const q = ($('#matrixFilter')?.value || '').toLowerCase();
  for (const r of results || []) {
    if (q && !((r.identity || '') + ' ' + (r.bodyPreview || '')).toLowerCase().includes(q)) continue;
    const reachable = r.status != null && r.status >= 200 && r.status < 300;
    const lowPriv = LOW_PRIV.test(r.identity);
    const vuln = reachable && lowPriv;
    const flag = r.error
      ? el('span', { class: 'flag-tag', text: 'error' })
      : reachable
      ? el('span', { class: 'flag-tag ' + (lowPriv ? 'flag-vuln' : 'flag-ok'), text: lowPriv ? 'REACHABLE ⚠' : 'reachable' })
      : el('span', { class: 'flag-tag flag-ok', text: 'denied' });

    const tr = el('tr', { class: vuln ? 'flagged' : '' }, [
      el('td', { text: r.identity }),
      el('td', {}, [
        r.error
          ? el('span', { text: 'ERR', style: 'color:var(--red)' })
          : el('span', { class: 'code-num ' + statusClass(r.status), text: String(r.status) }),
      ]),
      el('td', { text: r.size == null ? '–' : String(r.size) }),
      el('td', { text: r.timeMs == null ? '–' : r.timeMs + 'ms' }),
      el('td', {}, [flag]),
      el('td', { text: r.error || r.bodyPreview || '', title: r.bodyPreview || '' }),
    ]);
    tbody.appendChild(tr);
  }
}
