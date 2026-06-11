// Request tab: builder + repeater + response viewer.

import { $, $$, el, statusClass, fmtBytes, prettyJson, headersToText, copy } from './util.js';
import { state, identityHeaders, pushHistory } from './state.js';
import { sendProxy, buildCurl } from './api.js';
import { analyzeResponse } from './analyze.js';
import { goTab } from './util.js';
import { toFetch, toPython, toHttpie } from './codegen.js';

// --- URL helpers (shared) ----------------------------------------------

export function joinUrl(base, path) {
  if (/^https?:\/\//i.test(path)) return path;
  if (!base) return path;
  return base.replace(/\/$/, '') + (path.startsWith('/') ? '' : '/') + path;
}

// Build the absolute URL from the current Request-tab fields + query table.
export function currentUrl() {
  const raw = $('#reqUrl').value.trim();
  const base = state.baseUrl.trim();
  let url = joinUrl(base, raw);
  const params = readKv('#paramsTable').filter((p) => p.enabled && p.k);
  if (params.length) {
    const qs = params
      .map((p) => `${encodeURIComponent(p.k)}=${encodeURIComponent(p.v)}`)
      .join('&');
    url += (url.includes('?') ? '&' : '?') + qs;
  }
  return url;
}

export function getCurrentRequest({ withIdentity = true } = {}) {
  const tableHeaders = {};
  for (const h of readKv('#headersTable')) {
    if (h.enabled && h.k) tableHeaders[h.k] = h.v;
  }
  let headers = tableHeaders;
  if (withIdentity) {
    const merged = {};
    for (const [k, v] of Object.entries(identityHeaders())) {
      if (v !== null) merged[k] = v;
    }
    Object.assign(merged, tableHeaders); // table overrides identity
    headers = merged;
  }
  return {
    method: $('#reqMethod').value,
    url: currentUrl(),
    headers,
    body: $('#reqBody').value || null,
  };
}

// --- Endpoint loading ---------------------------------------------------

export function loadEndpoint(ep) {
  state.current = ep;
  $$('.endpoint').forEach((n) => n.classList.remove('active'));

  $('#reqMethod').value = ep.method;
  // Substitute path params with their example values inline.
  let path = ep.path;
  for (const p of ep.params.path) {
    path = path.replace(`{${p.name}}`, encodeURIComponent(p.example ?? p.name));
  }
  $('#reqUrl').value = path;

  // Query params table
  renderKv('#paramsTable', ep.params.query.map((p) => ({
    enabled: p.required,
    k: p.name,
    v: p.example == null ? '' : String(p.example),
  })));

  // Headers table: spec header params + content-type
  const headerRows = ep.params.header.map((p) => ({
    enabled: p.required,
    k: p.name,
    v: p.example == null ? '' : String(p.example),
  }));
  if (ep.body && ep.body.contentType) {
    headerRows.unshift({ enabled: true, k: 'Content-Type', v: ep.body.contentType });
  }
  renderKv('#headersTable', headerRows);

  // Body
  $('#reqBody').value = ep.body && ep.body.example != null
    ? JSON.stringify(ep.body.example, null, 2)
    : '';

  renderSummary(ep);
  goTab('request');
}

function renderSummary(ep) {
  const bits = [];
  if (ep.operationId) bits.push(`<code>${ep.operationId}</code>`);
  if (ep.summary) bits.push(ep.summary);
  if (ep.deprecated) bits.push('<span style="color:var(--red)">DEPRECATED</span>');
  const sec = (ep.security || []).flatMap((s) => Object.keys(s));
  if (sec.length) bits.push(`auth: ${[...new Set(sec)].join(', ')}`);
  else bits.push('<span style="color:var(--yellow)">no security defined</span>');
  $('#reqSummary').innerHTML = bits.join(' · ');
}

// --- Key/value tables ---------------------------------------------------

function renderKv(sel, rows) {
  const root = $(sel);
  root.innerHTML = '';
  for (const r of rows) addKvRow(root, r);
  if (!rows.length) addKvRow(root, { enabled: true, k: '', v: '' });
}

export function addKvRow(root, row = { enabled: true, k: '', v: '' }) {
  const node = el('div', { class: 'kv-row' }, [
    el('input', { type: 'checkbox', ...(row.enabled ? { checked: 'checked' } : {}) }),
    el('input', { type: 'text', class: 'k', value: row.k, placeholder: 'name' }),
    el('input', { type: 'text', class: 'v', value: row.v, placeholder: 'value' }),
    el('span', { class: 'del', text: '✕', onclick: () => node.remove() }),
  ]);
  root.appendChild(node);
}

function readKv(sel) {
  return $$('.kv-row', $(sel)).map((row) => {
    const inputs = row.querySelectorAll('input');
    return { enabled: inputs[0].checked, k: inputs[1].value.trim(), v: inputs[2].value };
  });
}

// --- Send + response ----------------------------------------------------

export async function sendCurrent() {
  const req = getCurrentRequest();
  if (!req.url) return;
  $('#sendBtn').disabled = true;
  $('#resStatus').innerHTML = '<span class="muted">Sending…</span>';
  const { result } = await sendProxy({ ...req, followRedirects: false });
  $('#sendBtn').disabled = false;
  renderResponse(result);
  pushHistory({
    method: req.method,
    url: req.url,
    status: result.status ?? null,
    size: result.size ?? null,
    timeMs: result.timeMs ?? null,
    error: result.error || null,
    request: req,
  });
}

export function renderResponse(result) {
  if (!result) return;
  if (result.error) {
    $('#resStatus').innerHTML = `<span class="code-num s-5xx">ERR</span> <span class="pill">${result.error}</span>`;
    $('#resBody').textContent = '';
    $('#resHeaders').textContent = '';
    renderAnalysis([]);
    return;
  }
  $('#resStatus').innerHTML =
    `<span class="code-num ${statusClass(result.status)}">${result.status} ${result.statusText}</span>` +
    `<span class="pill">${result.timeMs} ms</span>` +
    `<span class="pill">${fmtBytes(result.size)}${result.truncated ? ' (truncated)' : ''}</span>` +
    (result.redirected ? `<span class="pill">redirected → ${result.finalUrl}</span>` : '');
  const ct = result.headers['content-type'] || '';
  lastBodyText = ct.includes('json') ? prettyJson(result.body) : result.body;
  $('#resBody').textContent = lastBodyText;
  $('#resHeaders').textContent = headersToText(result.headers);
  renderAnalysis(analyzeResponse(result));
  applyResponseFind();
}

// --- Response find (highlight matches in the body) ----------------------

let lastBodyText = '';

function escapeHtml(s) {
  return s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}

function applyResponseFind() {
  const q = $('#resFind').value;
  const countEl = $('#resFindCount');
  if (!q) {
    $('#resBody').textContent = lastBodyText;
    countEl.textContent = '';
    return;
  }
  const lower = lastBodyText.toLowerCase();
  const needle = q.toLowerCase();
  let count = 0, idx = 0, html = '';
  while (true) {
    const found = lower.indexOf(needle, idx);
    if (found === -1) { html += escapeHtml(lastBodyText.slice(idx)); break; }
    html += escapeHtml(lastBodyText.slice(idx, found));
    html += '<mark>' + escapeHtml(lastBodyText.slice(found, found + q.length)) + '</mark>';
    idx = found + q.length;
    count++;
  }
  $('#resBody').innerHTML = html;
  countEl.textContent = count ? `${count} match${count > 1 ? 'es' : ''}` : 'no matches';
  const first = $('#resBody mark');
  if (first) first.scrollIntoView({ block: 'center' });
}

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

function renderAnalysis(findings) {
  const host = $('#resAnalysis');
  const badge = $('#analysisCount');
  host.innerHTML = '';
  if (!findings.length) {
    badge.textContent = '';
    host.innerHTML = '<span class="muted">No passive findings.</span>';
    return;
  }
  findings.sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  const high = findings.filter((f) => f.sev === 'high' || f.sev === 'medium').length;
  badge.textContent = String(findings.length);
  badge.classList.toggle('hot', high > 0);
  for (const f of findings) {
    host.appendChild(
      el('div', { class: 'finding f-' + f.sev }, [
        el('span', { class: 'sev-tag sev-' + f.sev, text: f.sev }),
        el('span', { class: 'finding-title', text: f.title }),
        el('span', { class: 'finding-note', text: f.note }),
      ])
    );
  }
}

// --- Wiring -------------------------------------------------------------

export function initRequest() {
  // populate method dropdown
  const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
  for (const sel of ['#reqMethod', '#matrixMethod']) {
    $(sel).innerHTML = methods.map((m) => `<option>${m}</option>`).join('');
  }

  $('#sendBtn').addEventListener('click', sendCurrent);
  $('#reqUrl').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendCurrent();
  });
  $('#addHeader').addEventListener('click', () => addKvRow($('#headersTable')));
  $('#addParam').addEventListener('click', () => addKvRow($('#paramsTable')));
  $('#prettyBody').addEventListener('click', () => {
    $('#reqBody').value = prettyJson($('#reqBody').value);
  });
  wireCodeModal();
  $('#resFind').addEventListener('input', applyResponseFind);

  // request-editor subtabs
  wireSubtabs('.req-editor', 'sub', 'subpanel');
  // response subtabs
  wireSubtabs('.res-view', 'res', 'respanel');
}

function wireCodeModal() {
  let lang = 'curl';
  const render = async () => {
    const req = getCurrentRequest();
    let out = '';
    if (lang === 'curl') out = (await buildCurl({ ...req, insecure: true })).curl;
    else if (lang === 'fetch') out = toFetch(req);
    else if (lang === 'python') out = toPython(req);
    else out = toHttpie(req);
    $('#codeOut').value = out;
  };
  $('#codeBtn').addEventListener('click', () => {
    $('#codeModal').hidden = false;
    render();
  });
  $('#closeCode').addEventListener('click', () => ($('#codeModal').hidden = true));
  $('#codeCopy').addEventListener('click', () => copy($('#codeOut').value));
  $$('#codeLangs .subtab').forEach((t) => {
    t.addEventListener('click', () => {
      $$('#codeLangs .subtab').forEach((x) => x.classList.remove('active'));
      t.classList.add('active');
      lang = t.dataset.lang;
      render();
    });
  });
}

function wireSubtabs(scope, dataKey, panelKey) {
  const root = $(scope);
  $$('.subtab', root).forEach((tab) => {
    tab.addEventListener('click', () => {
      $$('.subtab', root).forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      $$('.subpanel', root).forEach((p) =>
        p.classList.toggle('active', p.dataset[panelKey] === tab.dataset[dataKey])
      );
    });
  });
}
