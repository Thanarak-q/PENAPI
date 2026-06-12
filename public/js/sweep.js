// Auth Sweep: fire every spec endpoint as each identity and map which roles
// can reach what. Flags endpoints reachable by a low-privilege identity.

import { $, $$, el, statusClass, toast, textToHeaders } from './util.js';
import { state } from './state.js';
import { startSweep } from './api.js';
import { attachExport } from './export.js';

let rows = [];
let identityNames = [];
let abortFn = null;

const LOW_PRIV = /unauth|guest|anon|user|public|none|other/i;

export function initSweep() {
  $('#sweepStart').addEventListener('click', start);
  $('#sweepStop').addEventListener('click', stop);
  $('#sweepFilter').addEventListener('input', render);
  $('#sweepFlaggedOnly').addEventListener('change', render);
  renderIdentityChecks();

  attachExport(document.querySelector('[data-panel="sweep"] .results-toolbar'), () => ({
    name: 'swaggernaut-sweep',
    headers: ['method', 'path', 'hasSecurity', ...identityNames, 'flagged'],
    rows: rows.map((r) => {
      const row = { method: r.method, path: r.path, hasSecurity: r.hasSecurity, flagged: rowFlagged(r) };
      for (const n of identityNames) {
        const c = r.perIdentity[n];
        row[n] = c ? (c.error ? 'ERR' : `${c.status} (${c.size ?? '-'})`) : '';
      }
      return row;
    }),
  }));
}

// Re-render identity checkboxes (called after identities change).
export function renderIdentityChecks() {
  const host = $('#sweepIdentities');
  if (!host) return;
  host.innerHTML = state.identities
    .map(
      (i) =>
        `<label class="check"><input type="checkbox" class="sweepIdent" value="${i.name}" checked> ${i.name}</label>`
    )
    .join(' ');
}

function selectedMethods() {
  return $$('.sweepMethod:checked').map((c) => c.value);
}

function selectedIdentities() {
  const names = $$('.sweepIdent:checked').map((c) => c.value);
  return state.identities
    .filter((i) => names.includes(i.name))
    .map((i) => {
      const parsed = textToHeaders(i.headers);
      const headers = {};
      for (const [k, v] of Object.entries(parsed)) headers[k] = v === 'null' ? null : v;
      return { name: i.name, headers };
    });
}

function start() {
  const methods = selectedMethods();
  if (!methods.length) return toast('Pick at least one method', true);
  const identities = selectedIdentities();
  if (!identities.length) return toast('Pick at least one identity', true);

  const writeMethods = methods.filter((m) => !['GET', 'HEAD', 'OPTIONS'].includes(m));
  const estimatedEndpoints = (state.spec?.endpoints || []).filter((e) => methods.includes(e.method)).length;
  const concurrency = clamp(Number($('#sweepConc').value) || 3, 1, 10);
  $('#sweepConc').value = String(concurrency);
  const estimatedRequests = estimatedEndpoints * identities.length;
  const warning = [
    `Auth Sweep will send about ${estimatedRequests} real requests (${estimatedEndpoints} endpoints × ${identities.length} identities).`,
    `Concurrency: ${concurrency}.`,
    writeMethods.length
      ? `${writeMethods.join(', ')} may modify data.`
      : 'Safe methods can still be expensive on some APIs.',
    'Continue?',
  ].join('\n');
  if (!confirm(warning)) return;

  rows = [];
  identityNames = identities.map((i) => i.name);
  buildHead();
  render();
  $('#sweepStart').disabled = true;
  $('#sweepStop').disabled = false;

  abortFn = startSweep(
    {
      baseUrl: state.baseUrl,
      methods,
      identities,
      placeholder: $('#sweepPlaceholder').value || '1',
      concurrency,
    },
    {
      onStart: (d) => ($('#sweepProgress').textContent = `0 / ${d.total}`),
      onResult: (r) => {
        rows.push(r);
        $('#sweepProgress').textContent = `${r.done} / ${r.total}`;
        if (rows.length % 5 === 0 || rows.length < 30) render();
      },
      onDone: (d) => {
        finish();
        render();
        toast(`Sweep complete — ${d.total} endpoints`);
      },
      onError: (e) => {
        finish();
        toast('Sweep error: ' + e, true);
      },
    }
  );
}

function clamp(n, min, max) {
  return Math.min(Math.max(n, min), max);
}

function stop() {
  if (abortFn) abortFn();
  finish();
}

function finish() {
  $('#sweepStart').disabled = false;
  $('#sweepStop').disabled = true;
  abortFn = null;
}

function buildHead() {
  const head = $('#sweepHead');
  head.innerHTML = '';
  head.appendChild(el('th', { text: 'Method' }));
  head.appendChild(el('th', { text: 'Path' }));
  head.appendChild(el('th', { text: 'Sec' }));
  for (const name of identityNames) head.appendChild(el('th', { text: name }));
  head.appendChild(el('th', { text: 'Flag' }));
}

function statusCell(cell) {
  if (!cell) return el('td', { text: '–' });
  if (cell.error) return el('td', {}, [el('span', { text: 'ERR', style: 'color:var(--red)' })]);
  return el('td', {}, [
    el('span', { class: 'code-num ' + statusClass(cell.status), text: String(cell.status) }),
    el('span', { class: 'muted', text: cell.size != null ? ` ${cell.size}` : '' }),
  ]);
}

function rowFlagged(r) {
  for (const name of identityNames) {
    if (!LOW_PRIV.test(name)) continue;
    const c = r.perIdentity[name];
    if (c && c.status >= 200 && c.status < 300) return true;
  }
  return false;
}

function render() {
  const filter = $('#sweepFilter').value.toLowerCase();
  const flaggedOnly = $('#sweepFlaggedOnly').checked;
  const tbody = $('#sweepTable tbody');
  tbody.innerHTML = '';

  for (const r of rows) {
    const flagged = rowFlagged(r);
    if (flaggedOnly && !flagged) continue;
    if (filter && !r.path.toLowerCase().includes(filter)) continue;

    const tds = [
      el('td', {}, [el('span', { class: 'method-badge m-' + r.method.toLowerCase(), text: r.method })]),
      el('td', { text: r.path, title: r.url }),
      el('td', { text: r.hasSecurity ? '🔒' : '—', title: r.hasSecurity ? 'security defined' : 'no security in spec' }),
    ];
    for (const name of identityNames) tds.push(statusCell(r.perIdentity[name]));
    tds.push(
      el('td', {}, [
        flagged
          ? el('span', { class: 'flag-tag flag-vuln', text: 'AUTHZ ⚠' })
          : el('span', { class: 'muted', text: '' }),
      ])
    );
    tbody.appendChild(el('tr', { class: flagged ? 'flagged' : '' }, tds));
  }
}
