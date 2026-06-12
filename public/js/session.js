// Session manager: named profiles with switch / new / rename / delete /
// duplicate / import / export / edit-JSON. Persistence lives in state.js.

import { $, el, toast } from './util.js';
import {
  save, listProfiles, activeProfileName, switchProfile, createProfile,
  renameProfile, deleteProfile, duplicateProfile, getProfileData, setProfileData,
  exportProfile, importProfile,
} from './state.js';
import { download } from './export.js';

let onChange = () => {};

export function initSession(changeHandler) {
  onChange = changeHandler || (() => {});
  $('#closeSession')?.addEventListener('click', () => ($('#sessionModal').hidden = true));
  $('#sessNew')?.addEventListener('click', () => {
    const name = prompt('New profile name', 'New session');
    if (name === null) return;
    const created = createProfile(name || 'New session');
    switchProfile(created);
    afterChange();
    renderModal();
  });
  $('#sessExport')?.addEventListener('click', exportSession);
  $('#sessImport')?.addEventListener('click', importSession);
  $('#sessApplyJson')?.addEventListener('click', applyJson);
  $('#sessionFileInput')?.addEventListener('change', onFile);
  updateProfileLabel();
}

function afterChange() {
  updateProfileLabel();
  onChange();
}

export function updateProfileLabel() {
  const label = $('#profileName');
  if (label) label.textContent = activeProfileName();
}

// ---- File-menu actions -------------------------------------------------

export function saveSession() {
  save();
  toast('Session saved — ' + activeProfileName());
}

export function openSessions() {
  renderModal();
  $('#sessionModal').hidden = false;
}

export function exportSession() {
  const name = activeProfileName();
  const obj = exportProfile(name);
  download(
    `swaggernaut-session-${name.replace(/\s+/g, '-')}.json`,
    JSON.stringify(obj, null, 2),
    'application/json'
  );
}

export function importSession() {
  const input = $('#sessionFileInput');
  input.value = '';
  input.click();
}

function onFile(e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const obj = JSON.parse(reader.result);
      const name = importProfile(obj, obj && obj.name);
      switchProfile(name);
      afterChange();
      renderModal();
      $('#sessionModal').hidden = false;
      toast('Imported session — ' + name);
    } catch (err) {
      toast('Import failed: ' + err.message, true);
    }
  };
  reader.readAsText(file);
}

function applyJson() {
  try {
    const data = JSON.parse($('#sessionJson').value);
    setProfileData(activeProfileName(), data);
    afterChange();
    toast('Session updated');
  } catch (err) {
    toast('Invalid JSON: ' + err.message, true);
  }
}

// ---- Modal rendering ---------------------------------------------------

function renderModal() {
  const list = $('#sessionList');
  list.innerHTML = '';
  const active = activeProfileName();
  for (const name of listProfiles()) {
    const data = getProfileData(name);
    list.appendChild(
      el('div', { class: 'session-item' + (name === active ? ' active' : ''), onclick: () => select(name) }, [
        el('span', { class: 'sess-name', text: name }),
        el('span', { class: 'sess-meta', text: `${(data.identities || []).length} ids · ${(data.history || []).length} hist` }),
        el('span', { class: 'sess-acts' }, [
          el('span', { class: 'del', text: '✎', title: 'Rename', onclick: (e) => { e.stopPropagation(); rename(name); } }),
          el('span', { class: 'del', text: '⧉', title: 'Duplicate', onclick: (e) => { e.stopPropagation(); duplicateProfile(name); renderModal(); } }),
          el('span', { class: 'del', text: '✕', title: 'Delete', onclick: (e) => { e.stopPropagation(); remove(name); } }),
        ]),
      ])
    );
  }
  $('#sessionJson').value = JSON.stringify(getProfileData(active), null, 2);
}

function select(name) {
  if (switchProfile(name)) {
    afterChange();
    renderModal();
  }
}

function rename(name) {
  const next = prompt(`Rename profile "${name}" to:`, name);
  if (next === null) return;
  if (renameProfile(name, next)) {
    afterChange();
    renderModal();
  } else {
    toast('Rename failed (name in use?)', true);
  }
}

function remove(name) {
  if (!confirm(`Delete profile "${name}"? This cannot be undone.`)) return;
  if (deleteProfile(name)) {
    afterChange();
    renderModal();
  } else {
    toast('Cannot delete the last profile', true);
  }
}
