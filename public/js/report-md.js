// Pure Markdown report generator for the passive-analysis report. Produces a
// structured pentest-style document (executive summary, OWASP coverage, and
// findings grouped by severity) rather than a flat table. No DOM, no state.

import { OWASP_API } from './analyzers/owasp.js';
import { endpointRiskMap } from './analyzers/risk.js';

const SEV_ORDER = ['high', 'medium', 'low', 'info'];
const SEV_LABEL = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

function esc(value) {
  return String(value == null ? '' : value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function sevLine(severities = {}) {
  return SEV_ORDER.map((sev) => `${SEV_LABEL[sev]} ${severities[sev] || 0}`).join(' · ');
}

function owaspSection(owaspCounts = {}) {
  const ids = Object.keys(owaspCounts).sort();
  if (!ids.length) return [];
  const lines = [
    '## OWASP API Security Top 10 (2023) coverage',
    '',
    '| OWASP | Category | Findings |',
    '| --- | --- | --- |',
  ];
  for (const id of ids) {
    const meta = OWASP_API[id];
    lines.push(`| ${id} | ${meta ? esc(meta.title) : '—'} | ${owaspCounts[id]} |`);
  }
  lines.push('');
  return lines;
}

// Top endpoints ranked by aggregate passive-risk score.
function topRiskSection(report, limit = 10) {
  const ranked = [...endpointRiskMap(report).entries()]
    .map(([id, risk]) => ({ id, ...risk }))
    .sort((a, b) => b.score - a.score || b.count - a.count)
    .slice(0, limit);
  if (!ranked.length) return [];
  const lines = [
    '## Top risk endpoints',
    '',
    '| Endpoint | Score | High | Medium | Findings |',
    '| --- | --- | --- | --- | --- |',
  ];
  for (const r of ranked) {
    lines.push(`| \`${esc(r.id)}\` | ${r.score} | ${r.high} | ${r.medium} | ${r.count} |`);
  }
  lines.push('');
  return lines;
}

// Remediation appendix: one entry per triggered OWASP category.
function remediationSection(owaspCounts = {}) {
  const ids = Object.keys(owaspCounts).sort();
  if (!ids.length) return [];
  const lines = ['## Remediation by OWASP category', ''];
  for (const id of ids) {
    const meta = OWASP_API[id];
    if (!meta) continue;
    lines.push(`- **${id} ${esc(meta.title)}** — ${esc(meta.fix || '')}`);
  }
  lines.push('');
  return lines;
}

function findingBlock(finding, index) {
  const where = finding.method || finding.path ? `\`${[finding.method, finding.path].filter(Boolean).join(' ')}\`` : '—';
  const meta = [];
  if (finding.owasp) meta.push(`**OWASP:** ${finding.owasp}`);
  if (finding.cwe) meta.push(`**CWE:** ${finding.cwe}`);
  if (finding.confidence) meta.push(`**Confidence:** ${finding.confidence}`);
  const lines = [
    `#### ${index}. ${esc(finding.title)}`,
    `- **Endpoint:** ${where}`,
  ];
  if (meta.length) lines.push(`- ${meta.join(' · ')}`);
  if (finding.evidence) lines.push(`- **Evidence:** ${esc(finding.evidence)}`);
  if (finding.action) lines.push(`- **Action:** ${esc(finding.action)}`);
  lines.push('');
  return lines;
}

// Build the full Markdown report. `meta` may carry { title, target }.
export function toMarkdownReport(report, meta = {}) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  const summary = report?.summary || {};
  const title = meta.title || 'Swaggernaut — Passive API Security Report';

  const out = [`# ${title}`, '', `_Generated ${new Date().toISOString()}_`, ''];
  if (meta.target) out.push(`**Target:** ${esc(meta.target)}`, '');

  out.push(
    '## Summary',
    '',
    `- **Risk score:** ${summary.riskScore ?? 0} (posture: ${summary.grade || 'n/a'})`,
    `- **Findings:** ${summary.total ?? findings.length} — ${sevLine(summary.severities)}`,
    `- **Inputs:** ${summary.operations ?? 0} operations · ${summary.historyCount ?? 0} request logs`,
    `- **Spec findings:** ${summary.endpointFindings ?? 0} · **Log findings:** ${summary.logFindings ?? 0}`,
    ''
  );
  if (summary.authCoverage) {
    const c = summary.authCoverage;
    out.push(
      `- **Unauthenticated writes:** ${c.mutatingUnauth}/${c.mutating} mutating operations (${c.pct}%)`,
      `- **OWASP API categories triggered:** ${summary.owaspCategories ?? 0} / 10`,
      ''
    );
  }

  out.push(...owaspSection(summary.owasp));
  out.push(...topRiskSection(report));

  out.push('## Findings', '');
  if (!findings.length) {
    out.push('_No findings._', '');
  } else {
    for (const sev of SEV_ORDER) {
      const group = findings.filter((finding) => finding.sev === sev);
      if (!group.length) continue;
      out.push(`### ${SEV_LABEL[sev]} (${group.length})`, '');
      group.forEach((finding, i) => out.push(...findingBlock(finding, i + 1)));
    }
  }

  out.push(...remediationSection(summary.owasp));

  return out.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd() + '\n';
}
