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
  pinned: [], // endpoint ids the user has bookmarked
  endpointTags: {}, // endpoint id -> user-defined focus tags
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
  const { baseUrl, activeIdentity, identities, history, pinned, endpointTags } = state;
  localStorage.setItem(
    LS_KEY,
    JSON.stringify({ baseUrl, activeIdentity, identities, history: history.slice(0, 200), pinned, endpointTags })
  );
}

export function isPinned(id) {
  return state.pinned.includes(id);
}

export function togglePin(id) {
  if (isPinned(id)) state.pinned = state.pinned.filter((p) => p !== id);
  else state.pinned = [...state.pinned, id];
  save();
}

export function tagsFor(id) {
  return state.endpointTags[id] || [];
}

export function addEndpointTag(id, tag) {
  const cleaned = String(tag || '').trim().replace(/^#+/, '').replace(/\s+/g, '-').slice(0, 24);
  if (!cleaned) return;
  const next = [...new Set([...(state.endpointTags[id] || []), cleaned])];
  state.endpointTags = { ...state.endpointTags, [id]: next };
  save();
}

export function removeEndpointTag(id, tag) {
  const next = (state.endpointTags[id] || []).filter((t) => t !== tag);
  state.endpointTags = { ...state.endpointTags, [id]: next };
  if (!next.length) delete state.endpointTags[id];
  save();
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
