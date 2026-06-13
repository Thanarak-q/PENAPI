// Secret Scanner modal. Detection lives in the unit-tested secrets-core.js;
// this is render + wiring.

import { $, el, copy } from './util.js';
import { scanSecrets, summarizeSecrets } from './secrets-core.js';

function severityClass(severity) {
  if (severity === 'high') return 'flag-vuln';
  if (severity === 'medium') return 'flag-warn';
  return 'flag-ok';
}

function render() {
  const host = $('#secOut');
  host.innerHTML = '';
  const text = $('#secIn').value;
  if (!text.trim()) {
    host.appendChild(el('p', { class: 'hint', text: 'Paste a response body, JS bundle, config, or any text above.' }));
    return;
  }

  const findings = scanSecrets(text);
  if (!findings.length) {
    host.appendChild(el('span', { class: 'hint', text: 'No secrets detected.' }));
    return;
  }

  const summary = summarizeSecrets(findings);
  const summaryRow = el('div', { class: 'hdr-summary' });
  if (summary.high) {
    summaryRow.appendChild(el('span', { class: 'flag-tag flag-vuln', text: `${summary.high} high` }));
  }
  if (summary.medium) {
    summaryRow.appendChild(el('span', { class: 'flag-tag flag-warn', text: `${summary.medium} medium` }));
  }
  if (summary.low) {
    summaryRow.appendChild(el('span', { class: 'flag-tag flag-ok', text: `${summary.low} low` }));
  }
  summaryRow.appendChild(el('span', { class: 'muted', text: ` — ${summary.total} finding${summary.total === 1 ? '' : 's'}` }));
  host.appendChild(summaryRow);

  for (const f of findings) {
    const row = el('div', { class: 'hdr-row' });
    row.appendChild(el('span', { class: `flag-tag ${severityClass(f.severity)}`, text: f.severity }));
    row.appendChild(el('span', { class: 'hdr-note', text: f.type }));
    row.appendChild(el('code', { text: f.preview }));
    const copyBtn = el('button', {
      class: 'btn tiny ghost',
      text: 'copy',
      title: 'Copy the full matched value',
    });
    copyBtn.addEventListener('click', () => copy(f.match));
    row.appendChild(copyBtn);
    host.appendChild(row);
  }
}

export function openSecrets() {
  $('#secModal').hidden = false;
  $('#secIn').focus();
}

export function initSecrets() {
  $('#secRun').addEventListener('click', render);
  $('#secIn').addEventListener('input', render);
  $('#closeSec').addEventListener('click', () => ($('#secModal').hidden = true));
}
