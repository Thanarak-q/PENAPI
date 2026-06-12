// JSON Flattener — pure, DOM-free core. Flattens a parsed JSON value into a
// list of { path, value, type, sensitive } leaf rows using dot/bracket path
// notation, and flags keys whose name suggests sensitive data. Useful for
// spotting leaked fields and locating a value to extract in a Sequence step.
// DOM-free for `node --test`.

const SENSITIVE_RE = /(pass(word|wd)?|secret|token|api[_-]?key|auth|session|ssn|credit|card|cvv|private[_-]?key|access[_-]?key|client[_-]?secret|email|phone|dob|salt)/i;

// Flatten any JSON value into leaf rows. Arrays use [i] indices.
export function flatten(value, prefix = '') {
  const rows = [];
  walk(value, prefix, rows);
  return rows;
}

function walk(value, path, rows) {
  if (value === null || typeof value !== 'object') {
    rows.push(makeRow(path, value));
    return;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      rows.push({ path: path || '(root)', value: '[]', type: 'array', sensitive: false });
      return;
    }
    value.forEach((item, i) => walk(item, `${path}[${i}]`, rows));
    return;
  }
  const keys = Object.keys(value);
  if (keys.length === 0) {
    rows.push({ path: path || '(root)', value: '{}', type: 'object', sensitive: false });
    return;
  }
  for (const key of keys) {
    const childPath = path ? `${path}.${key}` : key;
    walk(value[key], childPath, rows);
  }
}

function makeRow(path, value) {
  const leafKey = String(path).split('.').pop() || path;
  return {
    path: path || '(root)',
    value: value === null ? 'null' : String(value),
    type: value === null ? 'null' : typeof value,
    sensitive: SENSITIVE_RE.test(leafKey),
  };
}

// Parse + flatten. Returns { ok, rows, error }.
export function flattenJson(text) {
  let parsed;
  try {
    parsed = JSON.parse(String(text || ''));
  } catch (e) {
    return { ok: false, rows: [], error: e.message };
  }
  return { ok: true, rows: flatten(parsed), error: null };
}

// Just the sensitive rows — quick "what leaked" view.
export function sensitiveRows(rows) {
  return (rows || []).filter((r) => r.sensitive);
}
