// Quick Attacks: run mutation variants of the current request and diff
// each result against the baseline to surface likely bypasses.

import { $, el, statusClass, toast } from './util.js';
import { getCurrentRequest } from './request.js';
import { runAttacks } from './api.js';

export function initAttacks() {
  $('#quickAttackBtn').addEventListener('click', run);
  $('#closeAttacks').addEventListener('click', () => ($('#attackModal').hidden = true));
}

async function run() {
  const req = getCurrentRequest();
  if (!req.url) return toast('Build a request first', true);
  const tbody = $('#attackTable tbody');
  tbody.innerHTML = '<tr><td colspan="6" class="muted">running variants…</td></tr>';
  $('#attackModal').hidden = false;

  const { ok, results, error } = await runAttacks(req);
  if (!ok) {
    tbody.innerHTML = '';
    return toast('Attack run failed: ' + error, true);
  }
  render(results);
}

function render(results) {
  const baseline = results.find((r) => r.name === 'baseline') || results[0];
  const baseStatus = baseline ? baseline.status : null;
  const tbody = $('#attackTable tbody');
  tbody.innerHTML = '';

  for (const r of results) {
    const isBaseline = r.name === 'baseline';
    const reachable = r.status != null && r.status >= 200 && r.status < 400;
    // A non-baseline variant that still succeeds is the interesting case —
    // strongest signal when the variant removed/own-goaled auth.
    const suspicious =
      !isBaseline && reachable &&
      /no auth|empty bearer|malformed|override|original|spoof|method/.test(r.name);
    const flag = r.error
      ? el('span', { class: 'flag-tag', text: 'error' })
      : isBaseline
      ? el('span', { class: 'flag-tag', text: 'ref' })
      : suspicious
      ? el('span', { class: 'flag-tag flag-vuln', text: 'BYPASS?' })
      : reachable
      ? el('span', { class: 'flag-tag', text: 'reachable' })
      : el('span', { class: 'flag-tag flag-ok', text: 'blocked' });

    const tr = el('tr', { class: suspicious ? 'flagged' : '' }, [
      el('td', { text: r.name }),
      el('td', { text: r.note, title: r.note }),
      el('td', {}, [
        r.error
          ? el('span', { text: 'ERR', style: 'color:var(--red)' })
          : el('span', { class: 'code-num ' + statusClass(r.status), text: String(r.status) }),
      ]),
      el('td', { text: r.size == null ? '–' : String(r.size) }),
      el('td', { text: r.timeMs == null ? '–' : r.timeMs + 'ms' }),
      el('td', {}, [flag]),
    ]);
    tbody.appendChild(tr);
  }
}
