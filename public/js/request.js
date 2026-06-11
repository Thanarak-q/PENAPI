// Request tab: builder + repeater + response viewer.

import { $, $$, el, statusClass, methodClass, fmtBytes, prettyJson, headersToText, copy } from './util.js';
import { state, identityHeaders, pushHistory, tagsFor } from './state.js';
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
  const params = readKv('#paramsTable').filter((p) => p.enabled && p.k);
  const pathParams = params.filter((p) => p.in === 'path');
  const queryParams = params.filter((p) => p.in !== 'path');
  let path = pathTemplate(raw, pathParams);
  for (const p of pathParams) {
    path = path.replace(new RegExp(`\\{${escapeRegExp(p.k)}\\}`, 'g'), encodeURIComponent(p.v));
  }
  let url = joinUrl(base, path);
  if (queryParams.length) {
    const qs = queryParams
      .map((p) => `${encodeURIComponent(p.k)}=${encodeURIComponent(p.v)}`)
      .join('&');
    url += (url.includes('?') ? '&' : '?') + qs;
  }
  return url;
}

function pathTemplate(raw, pathParams) {
  if (!pathParams.length) return raw;
  if (pathParams.some((p) => raw.includes(`{${p.k}}`))) return raw;
  const currentPath = state.current?.path || '';
  if (!pathParams.every((p) => currentPath.includes(`{${p.k}}`))) return raw;
  if (/^https?:\/\//i.test(raw)) {
    try {
      return new URL(raw).origin + currentPath;
    } catch {
      return raw;
    }
  }
  return currentPath;
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
  $('#reqUrl').value = ep.path;

  // Path + query params table. Path params are substituted into {tokens}
  // when building the outgoing URL; query params are appended as ?k=v.
  renderKv('#paramsTable', [
    ...ep.params.path.map((p) => ({
      in: 'path',
      enabled: true,
      k: p.name,
      v: p.example == null || p.example === '' ? p.name : String(p.example),
    })),
    ...ep.params.query.map((p) => ({
      in: 'query',
      enabled: p.required,
      k: p.name,
      v: p.example == null ? '' : String(p.example),
    })),
  ]);

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
  syncReqBodyHighlight();

  renderSummary(ep);
  renderCurrentEndpoint(ep);
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

function renderCurrentEndpoint(ep) {
  const method = $('#currentMethod');
  method.textContent = ep.method;
  method.className = 'method-badge ' + methodClass(ep.method);
  $('#currentPath').textContent = ep.path;
  $('#currentPath').title = ep.path;
  $('#currentSummary').textContent = ep.summary || ep.operationId || '';
  const tags = [...ep.tags, ...tagsFor(ep.id)];
  $('#currentTags').innerHTML = tags
    .map((tag) => `<span class="endpoint-tag">${escapeHtml(tag)}</span>`)
    .join('');
}

// --- Key/value tables ---------------------------------------------------

function renderKv(sel, rows) {
  const root = $(sel);
  root.innerHTML = '';
  for (const r of rows) addKvRow(root, r);
  if (!rows.length) addKvRow(root, { enabled: true, k: '', v: '' });
}

export function addKvRow(root, row = { enabled: true, k: '', v: '' }) {
  const paramIn = row.in || (root.id === 'paramsTable' ? 'query' : '');
  const node = el('div', { class: 'kv-row' }, [
    paramIn ? el('span', { class: 'kv-kind ' + paramIn, text: paramIn }) : null,
    el('input', { type: 'checkbox', ...(row.enabled ? { checked: 'checked' } : {}) }),
    el('input', { type: 'text', class: 'k', value: row.k, placeholder: 'name' }),
    el('input', { type: 'text', class: 'v', value: row.v, placeholder: 'value' }),
    el('span', { class: 'del', text: '✕', onclick: () => node.remove() }),
  ]);
  if (paramIn) node.dataset.in = paramIn;
  root.appendChild(node);
}

function readKv(sel) {
  return $$('.kv-row', $(sel)).map((row) => {
    const inputs = row.querySelectorAll('input');
    return {
      in: row.dataset.in || 'query',
      enabled: inputs[0].checked,
      k: inputs[1].value.trim(),
      v: inputs[2].value,
    };
  });
}

function escapeRegExp(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// --- Send + response ----------------------------------------------------

export async function sendCurrent() {
  const req = getCurrentRequest();
  if (!req.url) return;
  $('#sendBtn').disabled = true;
  $('#resStatus').innerHTML = '<span class="muted">Sending…</span>';
  const data = await sendProxy({ ...req, followRedirects: false });
  const result = data.result || { error: data.error || 'Request failed' };
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
    response: historyResponse(result),
  });
}

function historyResponse(result) {
  if (!result) return null;
  return {
    status: result.status ?? null,
    statusText: result.statusText || '',
    headers: result.headers || {},
    body: String(result.body || '').slice(0, 50000),
    size: result.size ?? null,
    timeMs: result.timeMs ?? null,
    error: result.error || null,
    truncated: !!result.truncated,
    finalUrl: result.finalUrl || '',
  };
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
  lastBodyIsJson = ct.includes('json');
  lastBodyText = lastBodyIsJson ? prettyJson(result.body) : result.body;
  $('#resHeaders').innerHTML = highlightHeaders(headersToText(result.headers));
  renderAnalysis(analyzeResponse(result));
  applyResponseFind();
}

// --- Response find (highlight matches in the body) ----------------------

let lastBodyText = '';
let lastBodyIsJson = false;

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}

function highlightJson(text) {
  const tokenRe = /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(?:true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;
  let html = '';
  let last = 0;
  for (const match of text.matchAll(tokenRe)) {
    const token = match[0];
    html += escapeHtml(text.slice(last, match.index));
    let cls = 'tok-number';
    if (token.startsWith('"')) cls = token.endsWith(':') ? 'tok-key' : 'tok-string';
    else if (token === 'true' || token === 'false') cls = 'tok-bool';
    else if (token === 'null') cls = 'tok-null';
    html += `<span class="${cls}">${escapeHtml(token)}</span>`;
    last = match.index + token.length;
  }
  html += escapeHtml(text.slice(last));
  return html;
}

function highlightHeaders(text) {
  return text
    .split('\n')
    .map((line) => {
      const idx = line.indexOf(':');
      if (idx === -1) return escapeHtml(line);
      const name = line.slice(0, idx);
      const value = line.slice(idx + 1);
      return `<span class="tok-header-name">${escapeHtml(name)}</span>:<span class="tok-header-value">${escapeHtml(value)}</span>`;
    })
    .join('\n');
}

function renderResponseBody() {
  if (!lastBodyText) {
    $('#resBody').textContent = '';
    return;
  }
  $('#resBody').innerHTML = lastBodyIsJson ? highlightJson(lastBodyText) : escapeHtml(lastBodyText);
}

function syncReqBodyHighlight() {
  const body = $('#reqBody');
  const highlight = $('#reqBodyHighlight');
  if (!body || !highlight) return;
  const text = body.value;
  highlight.innerHTML = text ? highlightJson(text) : '';
  highlight.scrollTop = body.scrollTop;
  highlight.scrollLeft = body.scrollLeft;
}

function applyResponseFind() {
  const q = $('#resFind').value;
  const countEl = $('#resFindCount');
  if (!q) {
    renderResponseBody();
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
    syncReqBodyHighlight();
  });
  $('#reqBody').addEventListener('input', syncReqBodyHighlight);
  $('#reqBody').addEventListener('scroll', syncReqBodyHighlight);
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
