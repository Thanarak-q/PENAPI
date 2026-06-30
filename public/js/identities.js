// Identity manager modal: named header sets for access-control testing.
// The editor presents the common case (a Bearer token) and an "unauth" toggle
// as first-class fields, with a key/value list for any other headers — but
// still serializes to the same newline `Name: value` text the rest of the app
// (state.identityHeaders, matrix) already understands.

import { $, $$, el } from './util.js';
import { state, save } from './state.js';

let onChange = () => {};

export function initIdentities(changeHandler) {
  onChange = changeHandler;
  $('#manageIdentities').addEventListener('click', open);
  $('#manageIdentitiesTop')?.addEventListener('click', open);
  $('#closeIdentities').addEventListener('click', close);
  $('#addIdentity').addEventListener('click', () => addCard({ name: 'New', headers: '' }));
  $('#saveIdentities').addEventListener('click', saveAll);
}

function open() {
  const editor = $('#identityEditor');
  editor.innerHTML = '';
  for (const id of state.identities) addCard(id);
  $('#identityModal').hidden = false;
}

function close() {
  $('#identityModal').hidden = true;
}

// Split a stored header blob into { bearer, strip, extra[] } for friendly editing.
function parseIdentity(headersText) {
  let bearer = '';
  let strip = false;
  const extra = [];
  for (const line of String(headersText || '').split('\n')) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const k = line.slice(0, idx).trim();
    const v = line.slice(idx + 1).trim();
    if (!k) continue;
    if (k.toLowerCase() === 'authorization') {
      if (v === 'null') strip = true;
      else if (/^Bearer\s+/i.test(v)) bearer = v.replace(/^Bearer\s+/i, '');
      else extra.push({ k, v });
    } else {
      extra.push({ k, v });
    }
  }
  return { bearer, strip, extra };
}

// Rebuild the stored header blob from a card's fields.
function serializeCard(card) {
  const lines = [];
  if (card.querySelector('.ident-strip').checked) {
    lines.push('Authorization: null');
  } else {
    const bearer = card.querySelector('.ident-bearer').value.trim();
    if (bearer) lines.push('Authorization: Bearer ' + bearer);
  }
  for (const row of $$('.ident-hrow', card)) {
    const k = row.querySelector('.k').value.trim();
    if (k) lines.push(`${k}: ${row.querySelector('.v').value}`);
  }
  return lines.join('\n');
}

function addCard(id) {
  const parsed = parseIdentity(id.headers);

  const headerRows = el('div', { class: 'ident-headers' });
  const addHeaderRow = (k = '', v = '') => {
    const row = el('div', { class: 'kv-row ident-hrow' }, [
      el('input', { type: 'text', class: 'k', value: k, placeholder: 'Header name' }),
      el('input', { type: 'text', class: 'v', value: v, placeholder: 'value' }),
      el('span', { class: 'del', text: '✕', onclick: () => row.remove() }),
    ]);
    headerRows.appendChild(row);
  };
  for (const r of parsed.extra) addHeaderRow(r.k, r.v);

  const stripBox = el('input', { type: 'checkbox', class: 'ident-strip', ...(parsed.strip ? { checked: 'checked' } : {}) });
  const bearerInput = el('input', {
    type: 'text', class: 'ident-bearer', value: parsed.bearer, spellcheck: 'false',
    placeholder: 'paste token / JWT — no "Bearer " prefix',
  });
  const syncStrip = () => { bearerInput.disabled = stripBox.checked; };
  stripBox.addEventListener('change', syncStrip);

  const card = el('div', { class: 'ident-card' }, [
    el('div', { class: 'ident-card-head' }, [
      el('input', { type: 'text', class: 'name', value: id.name, placeholder: 'identity name (e.g. Admin)' }),
      el('label', { class: 'check', title: 'Send no Authorization header (unauthenticated)' }, [stripBox, ' unauth']),
      el('span', { class: 'del', text: '✕', title: 'Remove identity', onclick: () => card.remove() }),
    ]),
    el('label', { class: 'ident-field' }, ['Bearer token', bearerInput]),
    el('div', { class: 'ident-extra' }, [
      el('div', { class: 'ident-extra-head' }, [
        'Extra headers',
        el('button', { class: 'btn tiny', type: 'button', text: '+ header', onclick: () => addHeaderRow() }),
      ]),
      headerRows,
    ]),
  ]);
  syncStrip();
  $('#identityEditor').appendChild(card);
}

function saveAll() {
  const cards = $$('#identityEditor .ident-card');
  state.identities = cards.map((card) => ({
    name: card.querySelector('.name').value.trim() || 'unnamed',
    headers: serializeCard(card),
  }));
  save();
  populateSelect();
  close();
  onChange();
}

export function populateSelect() {
  const sel = $('#identitySelect');
  sel.innerHTML =
    '<option value="none">— none —</option>' +
    state.identities.map((i) => `<option value="${i.name}">${i.name}</option>`).join('');
  sel.value = state.activeIdentity;
}
