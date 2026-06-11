// Fuzzer / brute-force tab. Streams results from the backend and flags
// anomalies (status or response-length deviating from the baseline).

import { $, $$, el, statusClass, toast, headersToText } from './util.js';
import { getCurrentRequest, currentUrl } from './request.js';
import { textToHeaders } from './util.js';
import { fetchPayloadSets, startFuzz } from './api.js';
import { attachExport } from './export.js';

let results = [];
let abortFn = null;
let sortKey = 'idx';
let sortDir = 1;

export async function initFuzzer() {
  const data = await fetchPayloadSets();
  const sel = $('#payloadSet');
  sel.innerHTML = '<option value="">— none —</option>' +
    (data.sets || []).map((s) => `<option value="${s.key}">${s.label} (${s.count})</option>`).join('');

  $('#loadFromRequest').addEventListener('click', loadFromRequest);
  $('#fuzzStart').addEventListener('click', start);
  $('#fuzzStop').addEventListener('click', stop);
  $('#fuzzFilter').addEventListener('input', renderTable);
  $('#anomalyOnly').addEventListener('change', renderTable);

  $$('#fuzzTable thead th[data-sort]').forEach((th) => {
    th.addEventListener('click', () => {
      const k = th.dataset.sort;
      sortDir = sortKey === k ? -sortDir : 1;
      sortKey = k;
      renderTable();
    });
  });

  attachExport(document.querySelector('[data-panel="fuzzer"] .results-toolbar'), () => ({
    name: 'penapi-fuzz',
    headers: ['idx', 'payload', 'status', 'size', 'timeMs', 'location', 'error'],
    rows: results,
  }));
}

function loadFromRequest() {
  // Pull the live request WITHOUT identity so markers survive, then keep
  // identity headers visible too.
  const req = getCurrentRequest({ withIdentity: true });
  $('#fuzzUrl').value = req.url;
  $('#fuzzHeaders').value = headersToText(req.headers);
  $('#fuzzBody').value = req.body || '';
  toast('Loaded current request — add §§ or FUZZ to mark injection points');
}

function buildTemplate() {
  return {
    method: $('#reqMethod').value,
    url: $('#fuzzUrl').value.trim(),
    headers: textToHeaders($('#fuzzHeaders').value),
    body: $('#fuzzBody').value || null,
  };
}

function start() {
  const template = buildTemplate();
  if (!template.url) return toast('No URL', true);

  const payloadsCfg = {
    builtin: $('#payloadSet').value || null,
    custom: $('#customPayloads').value || null,
    range: {
      start: $('#rangeStart').value !== '' ? Number($('#rangeStart').value) : null,
      end: $('#rangeEnd').value !== '' ? Number($('#rangeEnd').value) : null,
      step: Number($('#rangeStep').value) || 1,
    },
  };
  const options = {
    concurrency: Number($('#fuzzConc').value) || 10,
    delayMs: Number($('#fuzzDelay').value) || 0,
    followRedirects: $('#fuzzRedirects').checked,
  };

  results = [];
  renderTable();
  $('#fuzzStart').disabled = true;
  $('#fuzzStop').disabled = false;

  abortFn = startFuzz(
    { request: template, payloads: payloadsCfg, options },
    {
      onStart: (d) => ($('#fuzzProgress').textContent = `0 / ${d.total}`),
      onResult: (r) => {
        results.push(r);
        $('#fuzzProgress').textContent = `${r.done} / ${r.total}`;
        // Throttle re-render for large runs.
        if (results.length % 5 === 0 || results.length < 30) renderTable();
      },
      onDone: (d) => {
        finish();
        renderTable();
        toast(`Attack complete — ${d.total} requests`);
      },
      onError: (e) => {
        finish();
        toast('Fuzz error: ' + e, true);
      },
    }
  );
}

function stop() {
  if (abortFn) abortFn();
  finish();
}

function finish() {
  $('#fuzzStart').disabled = false;
  $('#fuzzStop').disabled = true;
  abortFn = null;
}

// Determine the baseline (modal) status and median length to flag outliers.
function computeBaseline() {
  const statusCounts = {};
  const sizes = [];
  for (const r of results) {
    if (r.error) continue;
    statusCounts[r.status] = (statusCounts[r.status] || 0) + 1;
    if (r.size != null) sizes.push(r.size);
  }
  let baseStatus = null, max = -1;
  for (const [s, c] of Object.entries(statusCounts)) {
    if (c > max) { max = c; baseStatus = Number(s); }
  }
  sizes.sort((a, b) => a - b);
  const medianSize = sizes.length ? sizes[Math.floor(sizes.length / 2)] : 0;
  return { baseStatus, medianSize };
}

function isAnomaly(r, base) {
  if (r.error) return true;
  if (base.baseStatus != null && r.status !== base.baseStatus) return true;
  if (base.medianSize && r.size != null) {
    const diff = Math.abs(r.size - base.medianSize);
    if (diff > Math.max(50, base.medianSize * 0.25)) return true;
  }
  return false;
}

function renderTable() {
  const base = computeBaseline();
  $('#fuzzBaseline').textContent =
    results.length && base.baseStatus != null
      ? `baseline: ${base.baseStatus} · median len ${base.medianSize}`
      : '';

  const filter = $('#fuzzFilter').value.toLowerCase();
  const anomalyOnly = $('#anomalyOnly').checked;

  let rows = results.slice();
  rows.sort((a, b) => {
    const av = a[sortKey], bv = b[sortKey];
    if (av == null) return 1;
    if (bv == null) return -1;
    return (av > bv ? 1 : av < bv ? -1 : 0) * sortDir;
  });

  const tbody = $('#fuzzTable tbody');
  tbody.innerHTML = '';
  for (const r of rows) {
    const anom = isAnomaly(r, base);
    if (anomalyOnly && !anom) continue;
    if (filter && !String(r.payload).toLowerCase().includes(filter)) continue;
    const tr = el('tr', { class: anom ? 'anomaly' : '' }, [
      el('td', { text: String(r.idx) }),
      el('td', { text: r.payload, title: r.payload }),
      el('td', {}, [
        r.error
          ? el('span', { text: 'ERR', style: 'color:var(--red)' })
          : el('span', { class: 'code-num ' + statusClass(r.status), text: String(r.status) }),
      ]),
      el('td', { text: r.size == null ? '–' : String(r.size) }),
      el('td', { text: r.timeMs == null ? '–' : r.timeMs + 'ms' }),
      el('td', { text: r.error || r.location || '', title: r.error || r.location || '' }),
      el('td', {}, [
        el('span', { class: 'del', text: '↪', title: 'open in Request tab', onclick: () => replay(r) }),
      ]),
    ]);
    tbody.appendChild(tr);
  }
}

// Re-issue a single fuzz result by loading it into the Request tab.
function replay(r) {
  const template = buildTemplate();
  const url = template.url.replace(/§[^§]*§/g, r.payload).replace(/\bFUZZ\b/g, r.payload);
  $('#reqUrl').value = url;
  $('#reqMethod').value = template.method;
  $('#reqBody').value = (template.body || '').replace(/§[^§]*§/g, r.payload).replace(/\bFUZZ\b/g, r.payload);
  $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === 'request'));
  $$('.panel').forEach((p) => p.classList.toggle('active', p.dataset.panel === 'request'));
  toast('Loaded payload #' + r.idx + ' into Request tab');
}
