// Identity manager modal: named header sets for access-control testing.

import { $, el } from './util.js';
import { state, save } from './state.js';

let onChange = () => {};

export function initIdentities(changeHandler) {
  onChange = changeHandler;
  $('#manageIdentities').addEventListener('click', open);
  $('#closeIdentities').addEventListener('click', close);
  $('#addIdentity').addEventListener('click', () =>
    addRow({ name: 'New', headers: '' })
  );
  $('#saveIdentities').addEventListener('click', saveAll);
}

function open() {
  const editor = $('#identityEditor');
  editor.innerHTML = '';
  for (const id of state.identities) addRow(id);
  $('#identityModal').hidden = false;
}

function close() {
  $('#identityModal').hidden = true;
}

function addRow(id) {
  const row = el('div', { class: 'ident-row' }, [
    el('input', { type: 'text', class: 'name', value: id.name, placeholder: 'name' }),
    el('textarea', {
      class: 'code',
      spellcheck: 'false',
      placeholder: 'Authorization: Bearer ...\nX-Api-Key: ...',
      text: id.headers,
    }),
    el('span', { class: 'del', text: '✕', onclick: () => row.remove() }),
  ]);
  $('#identityEditor').appendChild(row);
}

function saveAll() {
  const rows = [...$('#identityEditor').children];
  state.identities = rows.map((row) => ({
    name: row.querySelector('.name').value.trim() || 'unnamed',
    headers: row.querySelector('textarea').value,
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
