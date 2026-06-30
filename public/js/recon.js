// Attack Surface / Recon tab. Passive analysis only: summarizes the loaded
// spec and already-saved human request logs. It never sends requests.

import { $, el, methodClass } from './util.js';
import { state } from './state.js';
import { loadEndpoint } from './request.js';
import { attachExport, download } from './export.js';
import { getReport } from './report.js';
import { toMarkdownReport } from './report-md.js';
import { owaspLabel } from './analyzers/owasp.js';

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
let visibleFindings = [];
let exportReady = false;

export function initRecon() {
  $('#reconFilter')?.addEventListener('change', renderRecon);
  $('#reconTextFilter')?.addEventListener('input', renderRecon);
  if (!exportReady) {
    attachExport(document.querySelector('[data-panel="recon"] .results-toolbar'), () => ({
      name: 'static-analysis',
      headers: ['Severity', 'Category', 'OWASP', 'CWE', 'Confidence', 'Source', 'Method', 'Path', 'Finding', 'Evidence', 'Action'],
      rows: visibleFindings.map((finding) => ({
        Severity: finding.sev,
        Category: finding.category,
        OWASP: finding.owasp,
        CWE: finding.cwe,
        Confidence: finding.confidence,
        Source: finding.source,
        Method: finding.method,
        Path: finding.path,
        Finding: finding.title,
        Evidence: finding.evidence,
        Action: finding.action,
      })),
    }));
    addReportButton(document.querySelector('[data-panel="recon"] .results-toolbar .export-group'));
    exportReady = true;
  }
}

// Adds a structured-Markdown report download next to the table-export buttons.
function addReportButton(group) {
  if (!group) return;
  const btn = document.createElement('button');
  btn.className = 'btn ghost tiny';
  btn.textContent = 'Report';
  btn.title = 'Download a structured Markdown security report (summary, OWASP coverage, findings)';
  btn.addEventListener('click', () => {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const target = state.spec?.baseUrls?.[0] || state.spec?.title || '';
    download(`swaggernaut-report-${stamp}.md`, toMarkdownReport(getReport(), { target }), 'text/markdown');
  });
  group.appendChild(btn);
}

export function renderRecon() {
  if (!state.spec) return;
  const report = getReport();
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
    ['config', 'config'],
    ['resource', 'resource'],
    ['inventory', 'inventory'],
    ['quality', 'quality'],
    ['logs', 'logs'],
  ]
    .map(([key, label]) => `${label} ${summary.categories[key] || 0}`)
    .join('  ');
  const riskKind = summary.severities.high ? 'vuln' : summary.severities.medium ? 'warn' : '';
  const cov = summary.authCoverage || { mutating: 0, mutatingUnauth: 0, pct: 0 };
  const covKind = cov.pct >= 50 ? 'vuln' : cov.pct > 0 ? 'warn' : '';
  const cards = [
    ['Risk score', `${summary.riskScore} · ${summary.grade}`, riskKind],
    ['Findings', summary.total, summary.total ? 'warn' : ''],
    ['High', summary.severities.high, summary.severities.high ? 'vuln' : ''],
    ['Medium', summary.severities.medium, summary.severities.medium ? 'warn' : ''],
    ['Low', summary.severities.low, ''],
    ['Info', summary.severities.info, ''],
    ['Unauth writes', `${cov.mutatingUnauth}/${cov.mutating} · ${cov.pct}%`, covKind],
    ['OWASP cats', `${summary.owaspCategories || 0}/10`, summary.owaspCategories ? 'warn' : ''],
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
        el('td', { colspan: '8', text: 'No findings match the current filters.' }),
      ])
    );
    return;
  }

  for (const finding of list) {
    const endpoint = endpointFor(finding);
    const owasp = finding.owasp ? owaspLabel(finding.owasp) : '';
    const owaspTitle = [finding.owasp, finding.cwe, finding.confidence].filter(Boolean).join(' · ');

    const tr = el('tr', {}, [
      el('td', {}, [el('span', { class: `sev-tag sev-${finding.sev}`, text: finding.sev })]),
      el('td', {}, [el('span', { class: 'flag-tag', text: finding.source === 'history' ? 'log' : finding.category })]),
      el('td', {}, finding.method
        ? [el('span', { class: 'method-badge ' + methodClass(finding.method), text: finding.method })]
        : [el('span', { text: '—' })]),
      el('td', { text: finding.path || '—', title: finding.path || '' }),
      el('td', { text: finding.title, title: finding.action || finding.title }),
      el('td', owasp ? [el('span', { class: 'flag-tag', text: owasp, title: owaspTitle })] : [el('span', { class: 'muted', text: '—' })]),
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
