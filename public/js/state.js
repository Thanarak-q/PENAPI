// Central app state + localStorage persistence.
//
// Storage model: named "profiles" (sessions). Each profile holds a working
// setup; the *active* profile's fields are mirrored onto the flat `state.*`
// object so the rest of the app keeps using `state.baseUrl`, `state.identities`
// etc. with no changes. Persisted under `swaggernaut.session.v2`; older
// Swaggernaut/PenAPI blobs are migrated to `profiles.default`.

import { textToHeaders } from './util.js';
import { getSettings } from './settings.js';

const SESSION_KEY = 'swaggernaut.session.v2';
const LEGACY_KEY = 'swaggernaut.state.v1';
const PENAPI_SESSION_KEY = 'penapi.session.v2';
const PENAPI_LEGACY_KEY = 'penapi.state.v1';
const HISTORY_CAP = 200;

// Fields that belong to a profile (everything persisted per session).
const PROFILE_FIELDS = [
  'baseUrl',
  'activeIdentity',
  'identities',
  'history',
  'pinned',
  'endpointTags',
  'sequence',
  'matchReplace',
];

function blankProfile() {
  return {
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
    sequence: { steps: [] }, // saved Sequence Runner steps
    matchReplace: [], // Match & Replace rewrite rules
  };
}

// ---- load + migrate ----------------------------------------------------

function loadSession() {
  try {
    const raw = localStorage.getItem(SESSION_KEY) || localStorage.getItem(PENAPI_SESSION_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.profiles && Object.keys(parsed.profiles).length) {
        const activeProfile = parsed.profiles[parsed.activeProfile]
          ? parsed.activeProfile
          : Object.keys(parsed.profiles)[0];
        const profiles = {};
        for (const [name, data] of Object.entries(parsed.profiles)) {
          profiles[name] = { ...blankProfile(), ...data };
        }
        return { activeProfile, profiles };
      }
    }
    // Migrate a legacy single-session blob into profiles.default.
    const legacy = localStorage.getItem(LEGACY_KEY) || localStorage.getItem(PENAPI_LEGACY_KEY);
    if (legacy) {
      const data = { ...blankProfile(), ...JSON.parse(legacy) };
      return { activeProfile: 'default', profiles: { default: data } };
    }
  } catch {
    /* fall through to a fresh default */
  }
  return { activeProfile: 'default', profiles: { default: blankProfile() } };
}

const session = loadSession();

export const state = {
  spec: null,
  current: null, // currently selected endpoint
  activeProfile: session.activeProfile,
  profiles: session.profiles,
  ...session.profiles[session.activeProfile],
};

// ---- persistence -------------------------------------------------------

function snapshot() {
  const out = {};
  for (const f of PROFILE_FIELDS) out[f] = state[f];
  out.history = (out.history || []).slice(0, HISTORY_CAP);
  return structuredClone(out);
}

function applyProfileData(data) {
  const full = { ...blankProfile(), ...(data || {}) };
  for (const f of PROFILE_FIELDS) state[f] = full[f];
}

function persist() {
  const profiles = {};
  for (const [name, data] of Object.entries(state.profiles)) {
    profiles[name] = { ...data, history: (data.history || []).slice(0, HISTORY_CAP) };
  }
  localStorage.setItem(
    SESSION_KEY,
    JSON.stringify({ activeProfile: state.activeProfile, profiles })
  );
}

export function save() {
  state.profiles[state.activeProfile] = snapshot();
  persist();
}

// Make a migrated/default session durable immediately so the profile list is
// stable even before the first change.
if (!localStorage.getItem(SESSION_KEY)) persist();

// ---- profile (session) operations -------------------------------------

export function listProfiles() {
  return Object.keys(state.profiles);
}

export function activeProfileName() {
  return state.activeProfile;
}

function uniqueName(base) {
  let name = (base || 'session').trim() || 'session';
  if (!state.profiles[name]) return name;
  let i = 2;
  while (state.profiles[`${name} ${i}`]) i++;
  return `${name} ${i}`;
}

// Switch the active profile. Returns true on success. Caller re-renders.
export function switchProfile(name) {
  if (!state.profiles[name] || name === state.activeProfile) return false;
  state.profiles[state.activeProfile] = snapshot(); // capture current edits
  state.activeProfile = name;
  applyProfileData(state.profiles[name]);
  persist();
  return true;
}

export function createProfile(name, data) {
  const n = uniqueName(name);
  state.profiles[n] = { ...blankProfile(), ...(data || {}) };
  persist();
  return n;
}

export function renameProfile(oldName, newName) {
  const clean = (newName || '').trim();
  if (!clean || !state.profiles[oldName] || (state.profiles[clean] && clean !== oldName)) return false;
  if (clean === oldName) return true;
  state.profiles[clean] = state.profiles[oldName];
  delete state.profiles[oldName];
  if (state.activeProfile === oldName) state.activeProfile = clean;
  persist();
  return true;
}

export function deleteProfile(name) {
  if (!state.profiles[name] || listProfiles().length <= 1) return false;
  delete state.profiles[name];
  if (state.activeProfile === name) {
    state.activeProfile = listProfiles()[0];
    applyProfileData(state.profiles[state.activeProfile]);
  }
  persist();
  return true;
}

export function duplicateProfile(name, newName) {
  if (!state.profiles[name]) return null;
  if (name === state.activeProfile) save(); // capture latest before cloning
  const n = uniqueName(newName || `${name} copy`);
  state.profiles[n] = structuredClone(state.profiles[name]);
  persist();
  return n;
}

// Return a deep copy of a profile's data (active profile is snapshotted first).
export function getProfileData(name) {
  if (name === state.activeProfile) save();
  return structuredClone(state.profiles[name] || blankProfile());
}

// Replace a profile's data (used by Edit-JSON and import). Re-applies to the
// live state when it's the active profile. Caller re-renders.
export function setProfileData(name, data) {
  const clean = { ...blankProfile(), ...(data || {}) };
  state.profiles[name] = clean;
  if (name === state.activeProfile) applyProfileData(clean);
  persist();
  return true;
}

// ---- import / export ---------------------------------------------------

export function exportProfile(name) {
  return {
    _type: 'swaggernaut-session',
    version: 1,
    name,
    data: getProfileData(name),
  };
}

// Accepts either a wrapped {_type,name,data} export or a bare profile object.
export function importProfile(obj, nameHint) {
  const data = obj && obj.data ? obj.data : obj;
  const name = nameHint || (obj && obj.name) || 'imported';
  return createProfile(name, data);
}

// ---- tags --------------------------------------------------------------

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

// Usage counts for every custom tag across endpoints — Map(tag -> count).
export function tagUsage() {
  const counts = new Map();
  for (const tags of Object.values(state.endpointTags)) {
    for (const t of tags) counts.set(t, (counts.get(t) || 0) + 1);
  }
  return counts;
}

export function allTags() {
  return [...tagUsage().keys()].sort();
}

export function renameTag(oldTag, newTag) {
  const cleaned = String(newTag || '').trim().replace(/^#+/, '').replace(/\s+/g, '-').slice(0, 24);
  if (!cleaned || cleaned === oldTag) return false;
  const next = {};
  for (const [id, tags] of Object.entries(state.endpointTags)) {
    const replaced = [...new Set(tags.map((t) => (t === oldTag ? cleaned : t)))];
    if (replaced.length) next[id] = replaced;
  }
  state.endpointTags = next;
  save();
  return true;
}

export function deleteTag(tag) {
  const next = {};
  for (const [id, tags] of Object.entries(state.endpointTags)) {
    const filtered = tags.filter((t) => t !== tag);
    if (filtered.length) next[id] = filtered;
  }
  state.endpointTags = next;
  save();
  return true;
}

// ---- pins --------------------------------------------------------------

export function isPinned(id) {
  return state.pinned.includes(id);
}

export function togglePin(id) {
  if (isPinned(id)) state.pinned = state.pinned.filter((p) => p !== id);
  else state.pinned = [...state.pinned, id];
  save();
}

// ---- identities --------------------------------------------------------

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
  state.history = state.history.slice(0, getSettings().historyLimit);
  save();
}
