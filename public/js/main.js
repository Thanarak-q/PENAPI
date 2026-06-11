// Entry point: load spec, wire top bar / tabs / modals, init each tab module.

import { $, $$, toast, goTab } from './util.js';
import { state, save } from './state.js';
import { fetchSpec, parseCurl } from './api.js';
import { initExplorer, renderExplorer } from './explorer.js';
import { initRequest, loadEndpoint, sendCurrent } from './request.js';
import { initFuzzer, sendToFuzzer } from './fuzzer.js';
import { initMatrix, sendToMatrix } from './matrix.js';
import { initHistory, renderHistory } from './history.js';
import { initIdentities, populateSelect } from './identities.js';
import { initAttacks } from './attacks.js';
import { initSweep, renderIdentityChecks } from './sweep.js';
import { initJwt } from './jwt.js';
import { initSpecLoader, setSpecSourceLabel } from './spec.js';
import { initRecon, renderRecon } from './recon.js';

async function boot() {
  initRequest();
  await initFuzzer();
  initMatrix();
  initHistory();
  initExplorer(loadEndpoint);
  initAttacks();
  initSweep();
  initJwt();
  initIdentities(() => renderIdentityChecks());
  initRecon();
  initSpecLoader(applySpec);
  wireTopbar();
  wireTabs();
  wireCurlModal();
  wireCrossTab();
  wireShortcuts();

  await loadSpec();
  populateSelect();
  renderHistory();
}

// Apply a parsed spec to the app (used on boot and after loading a new spec).
function applySpec(spec, source) {
  state.spec = spec;
  $('#connDot').classList.add('ok');
  $('#connDot').classList.remove('bad');
  $('#specTitle').textContent = `${spec.title} ${spec.version} · ${spec.stats.endpoints} ops`;
  setSpecSourceLabel(source);
  // Default base URL from the spec if the user hasn't set one.
  if (!state.baseUrl && spec.baseUrls && spec.baseUrls[0]) {
    state.baseUrl = spec.baseUrls[0];
    save();
  }
  $('#baseUrl').value = state.baseUrl;
  renderExplorer();
}

async function loadSpec() {
  const dot = $('#connDot');
  try {
    const data = await fetchSpec();
    if (data.version) $('#brandVer').textContent = 'v' + data.version;
    if (!data.ok) {
      dot.classList.add('bad');
      $('#specTitle').textContent = 'no spec loaded — click “Load Spec”';
      setSpecSourceLabel(data.specSource);
      return;
    }
    applySpec(data.spec, data.specSource);
  } catch (e) {
    dot.classList.add('bad');
    toast('Server unreachable: ' + e.message, true);
  }
}

function wireTopbar() {
  $('#baseUrl').addEventListener('change', (e) => {
    state.baseUrl = e.target.value.trim();
    save();
  });
  $('#identitySelect').addEventListener('change', (e) => {
    state.activeIdentity = e.target.value;
    save();
  });
}

function wireTabs() {
  $$('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      $$('.tab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      $$('.panel').forEach((p) =>
        p.classList.toggle('active', p.dataset.panel === tab.dataset.tab)
      );
      if (tab.dataset.tab === 'history') renderHistory();
      if (tab.dataset.tab === 'recon') renderRecon();
    });
  });
}

function wireCrossTab() {
  $('#toFuzzerBtn').addEventListener('click', sendToFuzzer);
  $('#toMatrixBtn').addEventListener('click', sendToMatrix);
}

// Keyboard shortcuts for a faster workflow.
function wireShortcuts() {
  document.addEventListener('keydown', (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName);

    // Ctrl/Cmd+Enter — send the current request from anywhere.
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      goTab('request');
      sendCurrent();
      return;
    }
    // Esc — close any open modal.
    if (e.key === 'Escape') {
      $$('.modal-backdrop').forEach((m) => (m.hidden = true));
      return;
    }
    // "/" — focus the endpoint filter (when not already typing).
    if (e.key === '/' && !typing) {
      e.preventDefault();
      $('#endpointSearch').focus();
      return;
    }
    // Alt+1..8 — jump to a tab.
    if (e.altKey && /^[1-8]$/.test(e.key)) {
      const tabs = $$('.tab');
      const t = tabs[Number(e.key) - 1];
      if (t) {
        e.preventDefault();
        t.click();
      }
    }
  });
}

function wireCurlModal() {
  const modal = $('#curlModal');
  $('#importCurlBtn').addEventListener('click', () => (modal.hidden = false));
  $('#closeCurl').addEventListener('click', () => (modal.hidden = true));
  $('#doImportCurl').addEventListener('click', async () => {
    const text = $('#curlInput').value.trim();
    if (!text) return;
    const { ok, request, error } = await parseCurl(text);
    if (!ok) return toast('Parse failed: ' + error, true);
    applyParsedRequest(request);
    modal.hidden = true;
    toast('cURL imported');
  });
}

function applyParsedRequest(req) {
  $('#reqMethod').value = (req.method || 'GET').toUpperCase();
  $('#reqUrl').value = req.url || '';
  // headers table
  const root = $('#headersTable');
  root.innerHTML = '';
  for (const [k, v] of Object.entries(req.headers || {})) {
    addHeaderRow(root, k, v);
  }
  if (!Object.keys(req.headers || {}).length) addHeaderRow(root, '', '');
  $('#reqBody').value = req.body || '';
  // clear params (curl URL already includes the query string)
  $('#paramsTable').innerHTML = '';
  $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === 'request'));
  $$('.panel').forEach((p) => p.classList.toggle('active', p.dataset.panel === 'request'));
}

function addHeaderRow(root, k, v) {
  // Minimal inline row builder mirroring request.js addKvRow markup.
  const row = document.createElement('div');
  row.className = 'kv-row';
  row.innerHTML =
    '<input type="checkbox" checked>' +
    '<input type="text" class="k" placeholder="name">' +
    '<input type="text" class="v" placeholder="value">' +
    '<span class="del">✕</span>';
  row.querySelector('.k').value = k;
  row.querySelector('.v').value = v;
  row.querySelector('.del').addEventListener('click', () => row.remove());
  root.appendChild(row);
}

boot();
