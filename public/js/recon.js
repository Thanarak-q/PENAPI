// Attack Surface / Recon tab. Passive analysis only: summarizes the loaded
// spec and already-saved human request logs. It never sends requests.

import { $, el, methodClass } from './util.js';
import { state } from './state.js';
import { loadEndpoint } from './request.js';
import { attachExport } from './export.js';
import { analyzeSpec } from './static-analysis.js';

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
let visibleFindings = [];
let exportReady = false;

export function initRecon() {
  $('#reconFilter')?.addEventListener('change', renderRecon);
  $('#reconTextFilter')?.addEventListener('input', renderRecon);
  if (!exportReady) {
    attachExport(document.querySelector('[data-panel="recon"] .results-toolbar'), () => ({
      name: 'static-analysis',
      headers: ['Severity', 'Category', 'Source', 'Method', 'Path', 'Finding', 'Evidence', 'Action'],
      rows: visibleFindings.map((finding) => ({
        Severity: finding.sev,
        Category: finding.category,
        Source: finding.source,
        Method: finding.method,
        Path: finding.path,
        Finding: finding.title,
        Evidence: finding.evidence,
        Action: finding.action,
      })),
    }));
    exportReady = true;
  }
}

export function renderRecon() {
  if (!state.spec) return;
  const report = analyzeSpec(state.spec, state.history);
  renderCards(report.summary);
  visibleFindings = applyFilters(report.findings);
  renderList(visibleFindings);
}

function renderCards(summary) {
  const host = $('#reconCards');
  host.innerHTML = '';
  const categorySummary = [
    ['security', 'security'],
    ['idor', 'idor'],
    ['injection', 'injection'],
    ['data', 'data'],
    ['quality', 'quality'],
    ['logs', 'logs'],
  ]
    .map(([key, label]) => `${label} ${summary.categories[key] || 0}`)
    .join('  ');
  const cards = [
    ['Findings', summary.total, summary.total ? 'warn' : ''],
    ['High', summary.severities.high, summary.severities.high ? 'vuln' : ''],
    ['Medium', summary.severities.medium, summary.severities.medium ? 'warn' : ''],
    ['Low', summary.severities.low, ''],
    ['Info', summary.severities.info, ''],
    ['Spec findings', summary.endpointFindings, ''],
    ['Log findings', summary.logFindings, summary.logFindings ? 'warn' : ''],
    ['Inputs', `${summary.operations} ops · ${summary.historyCount} logs`, ''],
    ['Categories', categorySummary, 'wide'],
  ];
  for (const [label, value, kind] of cards) {
    host.appendChild(
      el('div', { class: 'recon-card' + (kind === 'wide' ? ' wide' : '') }, [
        el('div', { class: 'recon-val ' + (kind === 'vuln' ? 'rv-vuln' : kind === 'warn' ? 'rv-warn' : ''), text: String(value) }),
        el('div', { class: 'recon-label', text: label }),
      ])
    );
  }
}

function applyFilters(findings) {
  const filter = $('#reconFilter')?.value || 'auto';
  const q = ($('#reconTextFilter')?.value || '').trim().toLowerCase();
  return findings
    .filter((finding) => {
      if (filter === 'auto') return true;
      if (['high', 'medium', 'low', 'info'].includes(filter)) return finding.sev === filter;
      if (filter === 'logs') return finding.source === 'history' || finding.category === 'logs';
      return finding.category === filter;
    })
    .filter((finding) => {
      if (!q) return true;
      return [
        finding.sev,
        finding.category,
        finding.source,
        finding.method,
        finding.path,
        finding.title,
        finding.evidence,
        finding.action,
      ]
        .join(' ')
        .toLowerCase()
        .includes(q);
    })
    .sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
}

function renderList(list) {
  const tbody = $('#reconTable tbody');
  tbody.innerHTML = '';
  $('#reconCount').textContent = `${list.length} findings`;
  if (!list.length) {
    tbody.appendChild(
      el('tr', {}, [
        el('td', { colspan: '7', text: 'No findings match the current filters.' }),
      ])
    );
    return;
  }

  for (const finding of list) {
    const endpoint = endpointFor(finding);

    const tr = el('tr', {}, [
      el('td', {}, [el('span', { class: `sev-tag sev-${finding.sev}`, text: finding.sev })]),
      el('td', {}, [el('span', { class: 'flag-tag', text: finding.source === 'history' ? 'log' : finding.category })]),
      el('td', {}, finding.method
        ? [el('span', { class: 'method-badge ' + methodClass(finding.method), text: finding.method })]
        : [el('span', { text: '—' })]),
      el('td', { text: finding.path || '—', title: finding.path || '' }),
      el('td', { text: finding.title, title: finding.action || finding.title }),
      el('td', { text: finding.evidence || '', title: finding.evidence || '' }),
      el('td', {}, endpoint
        ? [el('span', { class: 'del', text: '→', title: 'open endpoint in Request tab', onclick: () => loadEndpoint(endpoint) })]
        : [el('span', { class: 'muted', text: '—' })]),
    ]);
    if (finding.sev === 'high') tr.classList.add('flagged');
    tbody.appendChild(tr);
  }
}

function endpointFor(finding) {
  if (!finding.endpointId) return null;
  return state.spec.endpoints.find((endpoint) => endpoint.id === finding.endpointId) || null;
}
