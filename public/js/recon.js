// Attack Surface / Recon tab. Summarizes the loaded spec to prioritize
// targets: unauthenticated operations, IDOR candidates (path params),
// mass-assignment candidates (request bodies), deprecated, etc. Client-only.

import { $, $$, el, methodClass } from './util.js';
import { state } from './state.js';
import { loadEndpoint } from './request.js';

const MUTATING = ['POST', 'PUT', 'PATCH', 'DELETE'];

export function initRecon() {
  $('#reconFilter')?.addEventListener('change', renderRecon);
}

export function renderRecon() {
  if (!state.spec) return;
  const eps = state.spec.endpoints;
  const noSec = eps.filter((e) => !(e.security && e.security.length));
  const idor = eps.filter((e) => e.params.path && e.params.path.length);
  const withBody = eps.filter((e) => e.body);
  const deprecated = eps.filter((e) => e.deprecated);
  const byMethod = {};
  for (const e of eps) byMethod[e.method] = (byMethod[e.method] || 0) + 1;

  // Highest-signal: mutating operations with no declared security.
  const dangerous = eps.filter(
    (e) => MUTATING.includes(e.method) && !(e.security && e.security.length)
  );

  renderCards([
    ['Total operations', eps.length, ''],
    ['No security defined', noSec.length, noSec.length ? 'warn' : ''],
    ['Mutating + unauth', dangerous.length, dangerous.length ? 'vuln' : ''],
    ['IDOR candidates (path id)', idor.length, ''],
    ['Mass-assignment (has body)', withBody.length, ''],
    ['Deprecated', deprecated.length, deprecated.length ? 'warn' : ''],
    ['Tags', state.spec.tags.length, ''],
    ['Methods', Object.entries(byMethod).map(([m, c]) => `${m} ${c}`).join('  '), 'wide'],
  ]);

  const filter = $('#reconFilter').value;
  let list;
  if (filter === 'unauth') list = noSec;
  else if (filter === 'dangerous') list = dangerous;
  else if (filter === 'idor') list = idor;
  else if (filter === 'body') list = withBody;
  else if (filter === 'deprecated') list = deprecated;
  else list = dangerous.length ? dangerous : noSec;

  renderList(list);
}

function renderCards(cards) {
  const host = $('#reconCards');
  host.innerHTML = '';
  for (const [label, value, kind] of cards) {
    host.appendChild(
      el('div', { class: 'recon-card' + (kind === 'wide' ? ' wide' : '') }, [
        el('div', { class: 'recon-val ' + (kind === 'vuln' ? 'rv-vuln' : kind === 'warn' ? 'rv-warn' : ''), text: String(value) }),
        el('div', { class: 'recon-label', text: label }),
      ])
    );
  }
}

function renderList(list) {
  const tbody = $('#reconTable tbody');
  tbody.innerHTML = '';
  for (const e of list) {
    const flags = [];
    if (!(e.security && e.security.length)) flags.push('unauth');
    if (MUTATING.includes(e.method) && !(e.security && e.security.length)) flags.push('danger');
    if (e.params.path && e.params.path.length) flags.push('idor');
    if (e.body) flags.push('body');
    if (e.deprecated) flags.push('deprecated');

    const tr = el('tr', {}, [
      el('td', {}, [el('span', { class: 'method-badge ' + methodClass(e.method), text: e.method })]),
      el('td', { text: e.path, title: e.summary || '' }),
      el('td', { text: (e.security && e.security.length) ? '🔒' : '—' }),
      el('td', { html: flags.map((f) => `<span class="flag-tag ${f === 'danger' ? 'flag-vuln' : ''}">${f}</span>`).join(' ') }),
      el('td', {}, [el('span', { class: 'del', text: '→', title: 'open in Request tab', onclick: () => loadEndpoint(e) })]),
    ]);
    tbody.appendChild(tr);
  }
}
