// Fuzzer / brute-force tab. Streams results from the backend and flags
// anomalies (status or response-length deviating from the baseline).

import { $, $$, el, statusClass, toast, headersToText, fmtBytes, prettyJson } from './util.js';
import { getCurrentRequest, currentUrl } from './request.js';
import { textToHeaders } from './util.js';
import { fetchPayloadSets, startFuzz, sendProxy } from './api.js';
import { attachExport } from './export.js';
import { goTab } from './util.js';
import { getSettings } from './settings.js';
import { suggestSets } from './analyzers/suggest.js';
import { wrapMarker, autoMarkUrl, autoMarkBody } from './fuzzmark-core.js';
import { analyzeResponse } from './analyze.js';
import { owaspLabel } from './analyzers/owasp.js';

let results = [];
let lastTemplateField = null;
let currentFuzzResult = null;
let abortFn = null;
let sortKey = 'idx';
let sortDir = 1;
const payloadSetCounts = {};
const payloadSetLabels = {};

export async function initFuzzer() {
  const data = await fetchPayloadSets();
  for (const s of data.sets || []) {
    payloadSetCounts[s.key] = s.count || 0;
    payloadSetLabels[s.key] = s.label || s.key;
  }
  const sel = $('#payloadSet');
  // Group sets into <optgroup>s by category, preserving server order.
  const esc = (v) => String(v).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const groups = new Map();
  for (const s of data.sets || []) {
    const cat = s.category || 'Other';
    if (!groups.has(cat)) groups.set(cat, []);
    groups.get(cat).push(s);
  }
  const optgroups = [...groups.entries()].map(([cat, sets]) =>
    `<optgroup label="${esc(cat)}">` +
    sets.map((s) => `<option value="${esc(s.key)}">${esc(s.label)} (${s.count})</option>`).join('') +
    '</optgroup>'
  ).join('');
  sel.innerHTML = '<option value="">— none —</option>' + optgroups;

  $('#loadFromRequest').addEventListener('click', loadFromRequest);
  // Track which template field was last focused so Insert §§ targets it.
  ['#fuzzUrl', '#fuzzBody', '#fuzzHeaders'].forEach((sel) =>
    $(sel).addEventListener('focus', () => (lastTemplateField = $(sel)))
  );
  $('#fuzzInsertMarker').addEventListener('click', insertMarker);
  $('#fuzzAutoMark').addEventListener('click', autoMark);
  $('#fuzzStart').addEventListener('click', start);

  // Fuzz response popup wiring.
  $('#closeFuzzResp').addEventListener('click', () => ($('#fuzzRespModal').hidden = true));
  $('#fuzzRespToRequest').addEventListener('click', () => {
    if (currentFuzzResult) replay(currentFuzzResult);
    $('#fuzzRespModal').hidden = true;
  });
  $$('#fuzzRespTabs .subtab').forEach((tab) =>
    tab.addEventListener('click', () => {
      $$('#fuzzRespTabs .subtab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      $$('[data-frpanel]').forEach((p) => p.classList.toggle('active', p.dataset.frpanel === tab.dataset.frtab));
    })
  );
  $('#fuzzStop').addEventListener('click', stop);
  $('#fuzzFilter').addEventListener('input', renderTable);
  $('#anomalyOnly').addEventListener('change', renderTable);
  $('#fuzzUrl').addEventListener('input', renderSuggestions);
  $('#fuzzBody').addEventListener('input', renderSuggestions);
  renderSuggestions();

  $$('#fuzzTable thead th[data-sort]').forEach((th) => {
    th.addEventListener('click', () => {
      const k = th.dataset.sort;
      sortDir = sortKey === k ? -sortDir : 1;
      sortKey = k;
      renderTable();
    });
  });

  attachExport(document.querySelector('[data-panel="fuzzer"] .results-toolbar'), () => ({
    name: 'swaggernaut-fuzz',
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
  renderSuggestions();
  toast('Loaded current request — add §§ or FUZZ to mark injection points');
}

// Wrap the selection in the last-focused template field with §…§, or insert an
// empty §§ at the caret.
function insertMarker() {
  const f = lastTemplateField || $('#fuzzUrl');
  f.focus();
  const start = f.selectionStart ?? f.value.length;
  const end = f.selectionEnd ?? f.value.length;
  const { value, caret } = wrapMarker(f.value, start, end);
  f.value = value;
  f.selectionStart = f.selectionEnd = caret;
  f.dispatchEvent(new Event('input'));
  renderSuggestions();
}

// Auto-mark a single likely injection point: prefer a body value, else the URL.
function autoMark() {
  const body = $('#fuzzBody').value;
  if (body.trim()) {
    const marked = autoMarkBody(body);
    if (marked) {
      $('#fuzzBody').value = marked;
      $('#fuzzBody').dispatchEvent(new Event('input'));
      renderSuggestions();
      return toast('Marked a body value — adjust if needed');
    }
  }
  const url = $('#fuzzUrl').value;
  const markedUrl = autoMarkUrl(url);
  if (markedUrl !== url) {
    $('#fuzzUrl').value = markedUrl;
    renderSuggestions();
    return toast('Marked a URL injection point');
  }
  toast('Nothing obvious to mark — select text and click Insert §§', true);
}

// Suggest the most relevant payload sets for the current request shape and let
// the tester pick one with a click instead of scrolling the whole picker.
function renderSuggestions() {
  const host = $('#fuzzSuggest');
  if (!host) return;
  const url = $('#fuzzUrl').value || '';
  const body = $('#fuzzBody').value || '';
  const headers = textToHeaders($('#fuzzHeaders').value || '');
  const contentType = headers['Content-Type'] || headers['content-type'] || '';
  const method = body ? 'POST' : 'GET';
  host.innerHTML = '';
  if (!url && !body) {
    host.hidden = true;
    return;
  }
  const suggestions = suggestSets({ url, body, method, contentType });
  if (!suggestions.length) {
    host.hidden = true;
    return;
  }
  host.hidden = false;
  host.appendChild(el('span', { class: 'meta', text: 'suggested:' }));
  for (const { key, why } of suggestions) {
    if (!payloadSetLabels[key]) continue;
    host.appendChild(
      el('button', {
        class: 'btn ghost tiny',
        text: payloadSetLabels[key],
        title: `${why} — click to select this set`,
        onclick: () => {
          $('#payloadSet').value = key;
          toast(`Selected ${payloadSetLabels[key]}`);
        },
      })
    );
  }
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
    concurrency: clamp(Number($('#fuzzConc').value) || 3, 1, 10),
    delayMs: Number($('#fuzzDelay').value) || 0,
    followRedirects: $('#fuzzRedirects').checked,
  };
  $('#fuzzConc').value = String(options.concurrency);

  const estimate = estimatePayloadCount(payloadsCfg);
  const writeMethod = !['GET', 'HEAD', 'OPTIONS'].includes((template.method || 'GET').toUpperCase());
  const risky = writeMethod || estimate > 20 || options.concurrency > 3 || options.delayMs === 0;
  if (risky) {
    const warning = [
      `Fuzzer will send about ${estimate || 'unknown'} real requests.`,
      `Concurrency: ${options.concurrency}, delay: ${options.delayMs}ms.`,
      writeMethod ? `${template.method} may modify data.` : 'GET/HEAD/OPTIONS can still be expensive on some APIs.',
      'Continue?',
    ].join('\n');
    const ok = !getSettings().confirmRisky || confirm(warning);
    if (!ok) return;
  }

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

function clamp(n, min, max) {
  return Math.min(Math.max(n, min), max);
}

function estimatePayloadCount(cfg) {
  let total = cfg.builtin ? payloadSetCounts[cfg.builtin] || 0 : 0;
  if (cfg.custom) total += String(cfg.custom).split('\n').filter((s) => s.length > 0).length;
  const r = cfg.range || {};
  if (r.start != null && r.end != null) {
    const step = Math.max(1, Math.abs(r.step || 1));
    total += Math.floor(Math.abs(r.end - r.start) / step) + 1;
  }
  return total;
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
        el('span', { class: 'del', text: '🔍', title: 'show response (popup)', onclick: () => showResponse(r) }),
        el('span', { class: 'del', text: '↪', title: 'open in Request tab', onclick: () => replay(r) }),
      ]),
    ]);
    tbody.appendChild(tr);
  }
}

// Re-issue a single fuzz result and show its full response in a popup, so the
// tester can inspect body/headers/findings without leaving the Fuzzer tab.
async function showResponse(r) {
  currentFuzzResult = r;
  const template = buildTemplate();
  const inject = (s) => (s || '').replace(/§[^§]*§/g, r.payload).replace(/\bFUZZ\b/g, r.payload);
  const headers = {};
  for (const [k, v] of Object.entries(template.headers)) headers[k] = inject(v);
  const req = {
    method: template.method,
    url: inject(template.url),
    headers,
    body: template.body != null ? inject(template.body) : null,
    followRedirects: $('#fuzzRedirects').checked,
  };
  $('#fuzzRespTitle').textContent = `#${r.idx} · ${r.payload}`;
  $('#fuzzRespStatus').innerHTML = '<span class="muted">Sending…</span>';
  $('#fuzzRespBody').textContent = '';
  $('#fuzzRespHeaders').textContent = '';
  $('#fuzzRespAnalysis').innerHTML = '';
  $('#fuzzRespModal').hidden = false;
  const data = await sendProxy(req);
  renderFuzzResponse(data.result || { error: data.error || 'Request failed' });
}

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

function renderFuzzResponse(result) {
  if (result.error) {
    $('#fuzzRespStatus').innerHTML = `<span class="code-num s-5xx">ERR</span> <span class="pill">${result.error}</span>`;
    renderFuzzFindings([]);
    return;
  }
  $('#fuzzRespStatus').innerHTML =
    `<span class="code-num ${statusClass(result.status)}">${result.status} ${result.statusText || ''}</span>` +
    `<span class="pill">${result.timeMs} ms</span>` +
    `<span class="pill">${fmtBytes(result.size)}${result.truncated ? ' (truncated)' : ''}</span>` +
    (result.redirected ? `<span class="pill">redirected → ${result.finalUrl}</span>` : '');
  const headers = result.headers || {};
  const ct = headers['content-type'] || headers['Content-Type'] || '';
  $('#fuzzRespBody').textContent = ct.includes('json') ? prettyJson(result.body) : (result.body || '');
  $('#fuzzRespHeaders').textContent = headersToText(headers);
  renderFuzzFindings(analyzeResponse(result));
}

function renderFuzzFindings(findings) {
  const host = $('#fuzzRespAnalysis');
  const badge = $('#fuzzRespAnalysisCount');
  host.innerHTML = '';
  if (!findings.length) {
    badge.textContent = '';
    host.innerHTML = '<span class="muted">No passive findings.</span>';
    return;
  }
  findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  badge.textContent = String(findings.length);
  for (const f of findings) {
    host.appendChild(
      el('div', { class: 'finding f-' + f.sev }, [
        el('span', { class: 'sev-tag sev-' + f.sev, text: f.sev }),
        el('span', { class: 'finding-title', text: f.title }),
        f.owasp ? el('span', { class: 'flag-tag', text: owaspLabel(f.owasp), title: [f.owasp, f.cwe].filter(Boolean).join(' · ') }) : null,
        el('span', { class: 'finding-note', text: f.note }),
      ])
    );
  }
}

// Re-issue a single fuzz result by loading it into the Request tab.
function replay(r) {
  const template = buildTemplate();
  const url = template.url.replace(/§[^§]*§/g, r.payload).replace(/\bFUZZ\b/g, r.payload);
  $('#reqUrl').value = url;
  $('#reqMethod').value = template.method;
  $('#reqBody').value = (template.body || '').replace(/§[^§]*§/g, r.payload).replace(/\bFUZZ\b/g, r.payload);
  $('#reqBody').dispatchEvent(new Event('input'));
  goTab('request');
  toast('Loaded payload #' + r.idx + ' into Request tab');
}

// Load the current request into the fuzzer and switch to it (cross-tab UX).
export function sendToFuzzer() {
  loadFromRequest();
  goTab('fuzzer');
}
