// Central app state + localStorage persistence.

import { textToHeaders } from './util.js';

const LS_KEY = 'penapi.state.v1';

const defaults = {
  baseUrl: '',
  activeIdentity: 'none',
  identities: [
    { name: 'Admin', headers: 'Authorization: Bearer REPLACE_ADMIN_TOKEN' },
    { name: 'User', headers: 'Authorization: Bearer REPLACE_USER_TOKEN' },
    { name: 'Unauth', headers: 'Authorization: null' },
  ],
  history: [],
};

export const state = {
  spec: null,
  current: null, // currently selected endpoint
  ...load(),
};

function load() {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return structuredClone(defaults);
    return { ...structuredClone(defaults), ...JSON.parse(raw) };
  } catch {
    return structuredClone(defaults);
  }
}

export function save() {
  const { baseUrl, activeIdentity, identities, history } = state;
  localStorage.setItem(
    LS_KEY,
    JSON.stringify({ baseUrl, activeIdentity, identities, history: history.slice(0, 200) })
  );
}

// Resolve the header set for the active identity (parsed). A value of the
// literal string "null" means strip that header.
export function identityHeaders() {
  const id = state.identities.find((i) => i.name === state.activeIdentity);
  if (!id) return {};
  const parsed = textToHeaders(id.headers);
  const out = {};
  for (const [k, v] of Object.entries(parsed)) {
    out[k] = v === 'null' ? null : v;
  }
  return out;
}

export function pushHistory(entry) {
  state.history.unshift({ ...entry, at: Date.now() });
  state.history = state.history.slice(0, 200);
  save();
}
