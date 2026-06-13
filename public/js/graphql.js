// GraphQL Toolkit modal. Logic lives in graphql-core.js; this is render + wiring.

import { $, el, copy, toast } from './util.js';
import { commonProbes, parseIntrospection, extractOperations } from './graphql-core.js';

function renderProbes() {
  const host = $('#gqlProbes');
  host.innerHTML = '';
  for (const probe of commonProbes()) {
    const btn = el('button', { class: 'btn tiny ghost', text: 'copy', title: 'Copy this probe query' });
    btn.addEventListener('click', () => { copy(probe.query); toast('Copied'); });
    host.appendChild(el('div', { class: 'pl-row' }, [
      el('span', { class: 'pl-payload', text: probe.label }),
      btn,
    ]));
  }
}

function renderParse() {
  const host = $('#gqlOut');
  host.innerHTML = '';
  const text = $('#gqlIn').value;
  if (!text.trim()) return;

  const parsed = parseIntrospection(text);
  if (!parsed.ok) {
    host.appendChild(el('span', { class: 'flag-tag flag-vuln', text: 'Parse error' }));
    host.appendChild(el('div', { class: 'hdr-note', text: parsed.error }));
    return;
  }

  host.appendChild(el('div', { class: 'rd-group-title', text: 'Root Types' }));
  for (const [label, val] of [
    ['Query', parsed.queryType],
    ['Mutation', parsed.mutationType],
    ['Subscription', parsed.subscriptionType],
  ]) {
    if (val) {
      host.appendChild(el('div', { class: 'jf-row' }, [
        el('span', { class: 'jf-path', text: label }),
        el('span', { class: 'jf-value', text: val }),
      ]));
    }
  }

  const ops = extractOperations(parsed);
  if (ops.queries.length || ops.mutations.length) {
    host.appendChild(el('div', { class: 'rd-group-title', text: 'Available Operations' }));
    if (ops.queries.length) {
      host.appendChild(el('div', { class: 'hdr-note', text: 'Queries: ' + ops.queries.join(', ') }));
    }
    if (ops.mutations.length) {
      host.appendChild(el('div', { class: 'hdr-note', text: 'Mutations: ' + ops.mutations.join(', ') }));
    }
  }

  if (parsed.types.length) {
    host.appendChild(el('div', { class: 'rd-group-title', text: `Types (${parsed.types.length})` }));
    for (const t of parsed.types) {
      host.appendChild(el('div', { class: 'jf-row' }, [
        el('span', { class: 'jf-path', text: t.name }),
        el('span', {
          class: 'jf-value',
          text: `${t.kind} · ${t.fieldCount} field${t.fieldCount !== 1 ? 's' : ''}`,
        }),
      ]));
    }
  }
}

export function openGraphql() {
  $('#gqlModal').hidden = false;
  $('#gqlIn').focus();
}

export function initGraphql() {
  renderProbes();
  $('#gqlIn').addEventListener('input', renderParse);
  $('#closeGql').addEventListener('click', () => ($('#gqlModal').hidden = true));
}
