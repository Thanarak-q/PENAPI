// Sequence Runner tab. Chains requests where captured response values feed
// later steps — multi-step flows, BOLA/IDOR setups, and token refresh. Runs
// sequentially and client-driven through the existing /api/proxy endpoint, so
// it inherits the same single-request safety posture (no new backend surface).

import { $, $$, el, statusClass, toast, textToHeaders, headersToText, goTab } from './util.js';
import { state, save, pushHistory } from './state.js';
import { getCurrentRequest, joinUrl } from './request.js';
import { sendProxy } from './api.js';
import { attachExport } from './export.js';
import { resolveStep, extractValues, evalAssertions } from './sequence-core.js';

const ACTIVE = '— active identity —';
const NONE = '— no identity —';

let steps = [];
let lastRows = [];
let running = false;

// --- persistence --------------------------------------------------------

function loadSteps() {
  const saved = state.sequence && Array.isArray(state.sequence.steps) ? state.sequence.steps : [];
  steps = saved.map(normalizeStep);
}

function persistSteps() {
  state.sequence = { steps };
  save();
}

function normalizeStep(s = {}) {
  return {
    method: (s.method || 'GET').toUpperCase(),
    url: s.url || '',
    identity: s.identity || ACTIVE,
    headers: s.headers || '',
    body: s.body || '',
    extract: Array.isArray(s.extract) ? s.extract.map((e) => ({ name: e.name || '', source: e.source || 'body', path: e.path || '' })) : [],
    assert: Array.isArray(s.assert) ? s.assert.map((a) => ({ source: a.source || 'status', path: a.path || '', op: a.op || 'eq', value: a.value ?? '' })) : [],
    stopOnFail: !!s.stopOnFail,
  };
}

// --- identity resolution (mirrors matrix.js null-strip semantics) -------

function identityHeadersFor(name) {
  if (name === NONE || name === ACTIVE && state.activeIdentity === 'none') return {};
  const target = name === ACTIVE ? state.activeIdentity : name;
  const id = state.identities.find((i) => i.name === target);
  if (!id) return {};
  const out = {};
  for (const [k, v] of Object.entries(textToHeaders(id.headers))) {
    if (v !== 'null') out[k] = v;
  }
  return out;
}

// --- step editor UI -----------------------------------------------------

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

function renderSteps() {
  const host = $('#seqSteps');
  host.innerHTML = '';
  if (!steps.length) {
    host.appendChild(el('p', { class: 'hint', text: 'No steps yet. Add a step, or load the current request as the first step.' }));
  }
  steps.forEach((step, i) => host.appendChild(renderStep(step, i)));
  $('#seqRun').disabled = running || steps.length === 0;
}

function select(value, options, onChange) {
  const node = el('select', { class: 'mini-select', onchange: (e) => onChange(e.target.value) });
  for (const opt of options) {
    const o = el('option', { value: opt, text: opt });
    if (opt === value) o.selected = true;
    node.appendChild(o);
  }
  return node;
}

function renderStep(step, i) {
  const identities = [ACTIVE, NONE, ...state.identities.map((id) => id.name)];
  const card = el('div', { class: 'seq-step' });

  const head = el('div', { class: 'seq-step-head' }, [
    el('span', { class: 'seq-num', text: String(i + 1) }),
    select(step.method, METHODS, (v) => { step.method = v; persistSteps(); }),
    el('input', {
      class: 'url-input', type: 'text', spellcheck: 'false', value: step.url,
      placeholder: '/path/{{capturedVar}}  or  https://…',
      oninput: (e) => { step.url = e.target.value; },
      onchange: persistSteps,
    }),
    select(step.identity, identities, (v) => { step.identity = v; persistSteps(); }),
    el('span', { class: 'del', text: '✕', title: 'remove step', onclick: () => { steps.splice(i, 1); persistSteps(); renderSteps(); } }),
  ]);

  const moves = el('div', { class: 'seq-moves' }, [
    el('button', { class: 'btn ghost tiny', text: '↑', title: 'move up', onclick: () => move(i, -1) }),
    el('button', { class: 'btn ghost tiny', text: '↓', title: 'move down', onclick: () => move(i, 1) }),
  ]);

  const headersField = el('textarea', {
    class: 'mono-area', rows: '2', placeholder: 'extra headers (one per line) — supports {{vars}}',
    oninput: (e) => { step.headers = e.target.value; },
    onchange: persistSteps,
  });
  headersField.value = step.headers;

  const bodyField = el('textarea', {
    class: 'mono-area', rows: '3', placeholder: 'request body — supports {{vars}}',
    oninput: (e) => { step.body = e.target.value; },
    onchange: persistSteps,
  });
  bodyField.value = step.body;

  card.appendChild(head);
  card.appendChild(moves);
  card.appendChild(el('div', { class: 'seq-grid' }, [
    el('label', { class: 'seq-label', text: 'Headers' }), headersField,
    el('label', { class: 'seq-label', text: 'Body' }), bodyField,
  ]));
  card.appendChild(renderExtractBlock(step));
  card.appendChild(renderAssertBlock(step));
  card.appendChild(el('label', { class: 'check seq-stop' }, [
    Object.assign(el('input', { type: 'checkbox', onchange: (e) => { step.stopOnFail = e.target.checked; persistSteps(); } }), { checked: step.stopOnFail }),
    document.createTextNode(' stop the run if this step’s checks fail'),
  ]));
  return card;
}

function move(i, dir) {
  const j = i + dir;
  if (j < 0 || j >= steps.length) return;
  [steps[i], steps[j]] = [steps[j], steps[i]];
  persistSteps();
  renderSteps();
}

function renderExtractBlock(step) {
  const rows = el('div', { class: 'seq-rows' });
  const draw = () => {
    rows.innerHTML = '';
    step.extract.forEach((ex, idx) => {
      rows.appendChild(el('div', { class: 'seq-row' }, [
        el('input', { type: 'text', class: 'k', value: ex.name, placeholder: 'var name', oninput: (e) => { ex.name = e.target.value; }, onchange: persistSteps }),
        el('span', { class: 'seq-from', text: 'from' }),
        select(ex.source, ['body', 'header', 'status'], (v) => { ex.source = v; persistSteps(); }),
        el('input', { type: 'text', class: 'v', value: ex.path, placeholder: 'path e.g. data.id', oninput: (e) => { ex.path = e.target.value; }, onchange: persistSteps }),
        el('span', { class: 'del', text: '✕', onclick: () => { step.extract.splice(idx, 1); persistSteps(); draw(); } }),
      ]));
    });
  };
  draw();
  return el('div', { class: 'seq-block' }, [
    el('div', { class: 'seq-block-head' }, [
      el('span', { class: 'seq-label', text: 'Capture' }),
      el('button', { class: 'btn ghost tiny', text: '+ value', onclick: () => { step.extract.push({ name: '', source: 'body', path: '' }); persistSteps(); draw(); } }),
    ]),
    rows,
  ]);
}

function renderAssertBlock(step) {
  const rows = el('div', { class: 'seq-rows' });
  const draw = () => {
    rows.innerHTML = '';
    step.assert.forEach((a, idx) => {
      const valueInput = el('input', { type: 'text', class: 'v', value: a.value, placeholder: 'value', oninput: (e) => { a.value = e.target.value; }, onchange: persistSteps });
      const sync = () => { valueInput.style.visibility = (a.op === 'exists' || a.op === 'notExists') ? 'hidden' : 'visible'; };
      const pathInput = el('input', { type: 'text', class: 'v', value: a.path, placeholder: 'path (blank for status)', oninput: (e) => { a.path = e.target.value; }, onchange: persistSteps });
      rows.appendChild(el('div', { class: 'seq-row' }, [
        select(a.source, ['status', 'body', 'header'], (v) => { a.source = v; persistSteps(); }),
        pathInput,
        select(a.op, ['eq', 'ne', 'contains', 'exists', 'notExists'], (v) => { a.op = v; sync(); persistSteps(); }),
        valueInput,
        el('span', { class: 'del', text: '✕', onclick: () => { step.assert.splice(idx, 1); persistSteps(); draw(); } }),
      ]));
      sync();
    });
  };
  draw();
  return el('div', { class: 'seq-block' }, [
    el('div', { class: 'seq-block-head' }, [
      el('span', { class: 'seq-label', text: 'Check' }),
      el('button', { class: 'btn ghost tiny', text: '+ check', onclick: () => { step.assert.push({ source: 'status', path: '', op: 'eq', value: '200' }); persistSteps(); draw(); } }),
    ]),
    rows,
  ]);
}

// --- run ----------------------------------------------------------------

async function run() {
  if (running || !steps.length) return;
  const writeSteps = steps.filter((s) => !['GET', 'HEAD', 'OPTIONS'].includes(s.method));
  if (writeSteps.length) {
    if (!confirm(`This sequence runs ${steps.length} real request(s), ${writeSteps.length} of which may modify data. Continue?`)) return;
  }

  running = true;
  $('#seqRun').disabled = true;
  $('#seqStop').disabled = false;
  lastRows = [];
  renderResults();

  const vars = { baseUrl: state.baseUrl || '' };
  for (let i = 0; i < steps.length && running; i++) {
    const step = steps[i];
    const resolved = resolveStep({ ...step, headers: textToHeaders(step.headers) }, vars);
    const url = joinUrl(state.baseUrl, resolved.url);
    const headers = { ...identityHeadersFor(step.identity), ...resolved.headers };
    const row = { idx: i + 1, method: resolved.method, url, status: null, timeMs: null, size: null, captured: {}, checks: { ok: true, checks: [] }, error: null };
    lastRows.push(row);
    renderResults();

    let result;
    try {
      const data = await sendProxy({ method: resolved.method, url, headers, body: resolved.body, followRedirects: false });
      result = data.result || { error: data.error || 'Request failed' };
    } catch (e) {
      result = { error: e.message };
    }

    row.status = result.status ?? null;
    row.timeMs = result.timeMs ?? null;
    row.size = result.size ?? null;
    row.error = result.error || null;

    pushHistory({
      method: resolved.method,
      url,
      status: result.status ?? null,
      size: result.size ?? null,
      timeMs: result.timeMs ?? null,
      error: result.error || null,
      request: { method: resolved.method, url, headers, body: resolved.body },
      response: result.error ? null : {
        status: result.status ?? null,
        statusText: result.statusText || '',
        headers: result.headers || {},
        body: String(result.body || '').slice(0, 50000),
        size: result.size ?? null,
        timeMs: result.timeMs ?? null,
        finalUrl: result.finalUrl || '',
      },
    });

    if (!result.error) {
      row.captured = extractValues(result, step.extract);
      Object.assign(vars, row.captured);
      row.checks = evalAssertions(result, step.assert);
    } else {
      row.checks = { ok: false, checks: [{ ok: false, label: result.error }] };
    }
    renderResults();

    if ((row.error || !row.checks.ok) && step.stopOnFail) {
      toast(`Stopped at step ${i + 1} — checks failed`, true);
      break;
    }
  }

  running = false;
  $('#seqRun').disabled = steps.length === 0;
  $('#seqStop').disabled = true;
}

function renderResults() {
  const tbody = $('#seqTable tbody');
  tbody.innerHTML = '';
  for (const r of lastRows) {
    const captured = Object.entries(r.captured || {}).map(([k, v]) => `${k}=${v}`).join(', ');
    const checks = r.checks.checks.length
      ? el('span', {}, r.checks.checks.map((c) =>
          el('span', { class: 'flag-tag ' + (c.ok ? 'flag-ok' : 'flag-vuln'), text: c.label, title: c.label })))
      : el('span', { class: 'muted', text: '–' });
    tbody.appendChild(el('tr', { class: r.error || !r.checks.ok ? 'flagged' : '' }, [
      el('td', { text: String(r.idx) }),
      el('td', {}, [el('span', { class: 'method-badge m-' + r.method.toLowerCase(), text: r.method })]),
      el('td', { text: r.url, title: r.url }),
      el('td', {}, [
        r.error
          ? el('span', { text: 'ERR', style: 'color:var(--red)', title: r.error })
          : el('span', { class: 'code-num ' + statusClass(r.status), text: r.status == null ? '…' : String(r.status) }),
      ]),
      el('td', { text: r.timeMs == null ? '–' : r.timeMs + 'ms' }),
      el('td', { text: captured || '–', title: captured }),
      el('td', {}, [checks]),
    ]));
  }
}

// --- wiring -------------------------------------------------------------

function stepFromRequest() {
  const req = getCurrentRequest({ withIdentity: false });
  return normalizeStep({
    method: req.method,
    url: req.url,
    identity: ACTIVE,
    headers: headersToText(req.headers),
    body: req.body || '',
  });
}

export function sendToSequence() {
  steps.push(stepFromRequest());
  persistSteps();
  renderSteps();
  goTab('sequence');
  toast('Added current request as step ' + steps.length);
}

export function initSequence() {
  loadSteps();
  renderSteps();

  $('#seqAddStep').addEventListener('click', () => { steps.push(normalizeStep({})); persistSteps(); renderSteps(); });
  $('#seqAddFromReq').addEventListener('click', () => { steps.push(stepFromRequest()); persistSteps(); renderSteps(); });
  $('#seqClear').addEventListener('click', () => {
    if (steps.length && !confirm('Clear all steps in this sequence?')) return;
    steps = [];
    persistSteps();
    renderSteps();
    lastRows = [];
    renderResults();
  });
  $('#seqRun').addEventListener('click', run);
  $('#seqStop').addEventListener('click', () => { running = false; });

  attachExport(document.querySelector('[data-panel="sequence"] .seq-toolbar'), () => ({
    name: 'swaggernaut-sequence',
    headers: ['idx', 'method', 'url', 'status', 'timeMs', 'captured', 'checks'],
    rows: lastRows.map((r) => ({
      idx: r.idx, method: r.method, url: r.url, status: r.status, timeMs: r.timeMs,
      captured: Object.entries(r.captured || {}).map(([k, v]) => `${k}=${v}`).join('; '),
      checks: r.checks.checks.map((c) => `${c.ok ? 'PASS' : 'FAIL'} ${c.label}`).join('; '),
    })),
  }));
}

// Re-render the editor when the active profile changes (identity lists, steps).
export function renderSequence() {
  loadSteps();
  renderSteps();
}
