// Sequence Runner — pure, DOM-free core. Chains requests where values from
// one response are captured and interpolated into later requests (the missing
// primitive behind IDOR autopilot, auth-token refresh, and multi-step flows).
//
// Kept side-effect free so it can be unit-tested under `node --test`. All DOM
// and network concerns live in sequence.js.

// Resolve a dotted/bracket path against a parsed object.
//   getByPath({a:{b:[{c:7}]}}, 'a.b[0].c') === 7
// Returns undefined for any missing segment (never throws).
export function getByPath(obj, path) {
  if (path == null || path === '') return obj;
  const parts = String(path)
    .replace(/\[(\d+)\]/g, '.$1') // a[0] -> a.0
    .replace(/^\./, '')
    .split('.')
    .filter((p) => p !== '');
  let cur = obj;
  for (const part of parts) {
    if (cur == null) return undefined;
    cur = cur[part];
  }
  return cur;
}

// Parse a response body string as JSON, returning null when it is not JSON.
export function parseBody(body) {
  if (body == null) return null;
  if (typeof body === 'object') return body;
  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
}

// Names of the {{tokens}} referenced in a string (deduped, in order).
export function findVars(text) {
  const out = [];
  for (const m of String(text ?? '').matchAll(/\{\{\s*([\w.-]+)\s*\}\}/g)) {
    if (!out.includes(m[1])) out.push(m[1]);
  }
  return out;
}

// Replace every {{name}} token with vars[name]. Unknown tokens are left intact
// so a misconfigured step is visible rather than silently blanked.
export function interpolate(text, vars = {}) {
  if (text == null) return text;
  return String(text).replace(/\{\{\s*([\w.-]+)\s*\}\}/g, (whole, name) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name] ?? '') : whole
  );
}

// Read one value out of a proxy response result.
//   def = { source: 'status' | 'header' | 'body', path }
export function readValue(result, def) {
  if (!result || !def) return undefined;
  if (def.source === 'status') return result.status;
  if (def.source === 'header') {
    const headers = result.headers || {};
    const key = String(def.path || '').toLowerCase();
    return headers[key];
  }
  // body (default): JSON path into the parsed body
  return getByPath(parseBody(result.body), def.path);
}

// Capture all extract defs from a response into a { name: value } bag.
// Defs without a name, or that resolve to undefined, are skipped.
export function extractValues(result, defs = []) {
  const out = {};
  for (const def of defs) {
    const name = String(def.name || '').trim();
    if (!name) continue;
    const value = readValue(result, def);
    if (value !== undefined) out[name] = value;
  }
  return out;
}

// Evaluate a single assertion against a response.
//   assert = { source, path, op: 'eq'|'ne'|'contains'|'exists'|'notExists', value }
// Returns { ok, actual, label }.
export function evalAssertion(result, assert) {
  const actual = readValue(result, assert);
  const op = assert.op || 'exists';
  const expected = assert.value;
  let ok;
  switch (op) {
    case 'exists':
      ok = actual !== undefined && actual !== null;
      break;
    case 'notExists':
      ok = actual === undefined || actual === null;
      break;
    case 'ne':
      ok = String(actual) !== String(expected);
      break;
    case 'contains':
      ok = String(actual ?? '').includes(String(expected ?? ''));
      break;
    case 'eq':
    default:
      ok = String(actual) === String(expected);
      break;
  }
  const target = assert.source === 'status'
    ? 'status'
    : `${assert.source}:${assert.path || ''}`;
  return { ok, actual, label: `${target} ${op} ${expected ?? ''}`.trim() };
}

// Evaluate every assertion; { ok } is true only when all pass (empty = pass).
export function evalAssertions(result, asserts = []) {
  const checks = asserts
    .filter((a) => a && a.source)
    .map((a) => evalAssertion(result, a));
  return { ok: checks.every((c) => c.ok), checks };
}

// Build the concrete request for a step by interpolating the running var bag
// into its url, headers, and body. Pure: callers supply the vars and merge in
// identity headers / base URL joining themselves.
export function resolveStep(step, vars = {}) {
  const headers = {};
  for (const [k, v] of Object.entries(step.headers || {})) {
    headers[interpolate(k, vars)] = interpolate(v, vars);
  }
  return {
    method: (step.method || 'GET').toUpperCase(),
    url: interpolate(step.url || '', vars),
    headers,
    body: step.body ? interpolate(step.body, vars) : null,
  };
}
