// Shared, dependency-free helpers for the passive analyzer layer.
//
// Every analyzer module is *pure*: it receives a context object and returns an
// array of "finding specs" (plain objects). It never fetches, sends, mutates
// global state, or reaches into the DOM. The orchestrator in static-analysis.js
// normalizes each spec through `makeFinding` and merges the results.
//
// Finding spec shape (all fields except sev/category/title are optional):
//   {
//     sev:        'high' | 'medium' | 'low' | 'info',
//     category:   one of CATEGORIES (see static-analysis.js),
//     title:      short human label,
//     endpoint:   { id, method, path } | null,   // for spec-derived findings
//     method, path,                              // for log findings with no matched endpoint
//     source:     'spec' | 'history'   (default 'spec'),
//     evidence:   short string of supporting detail,
//     action:     remediation / next-step guidance,
//     owasp:      OWASP API Security Top 10 id, e.g. 'API8:2023',
//     cwe:        CWE id, e.g. 'CWE-942',
//     confidence: 'firm' | 'tentative'  (default 'firm'),
//   }

export const SEVERITIES = ['high', 'medium', 'low', 'info'];
export const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
export const SEV_WEIGHT = { high: 10, medium: 4, low: 1, info: 0 };

// Normalize a finding spec into the canonical finding object used everywhere.
export function makeFinding({
  sev,
  category,
  title,
  endpoint,
  evidence,
  action,
  source = 'spec',
  owasp = '',
  cwe = '',
  confidence = 'firm',
}) {
  return {
    sev,
    category,
    title,
    source,
    method: endpoint?.method || '',
    path: endpoint?.path || '',
    endpointId: endpoint?.id || '',
    evidence: evidence || '',
    action: action || '',
    owasp: owasp || '',
    cwe: cwe || '',
    confidence: confidence || 'firm',
  };
}

// ---- header helpers --------------------------------------------------------

export function lowerHeaders(headers) {
  const out = {};
  for (const [key, value] of Object.entries(headers || {})) out[String(key).toLowerCase()] = value;
  return out;
}

// Case-insensitive header lookup. Accepts a raw or already-lowercased map.
export function getHeader(headers, name) {
  if (!headers) return undefined;
  const want = String(name).toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (String(key).toLowerCase() === want) return value;
  }
  return undefined;
}

// ---- URL helpers -----------------------------------------------------------

export function pathFromUrl(url) {
  try {
    return new URL(url).pathname || '/';
  } catch {
    const raw = String(url || '');
    return raw.split(/[?#]/)[0] || '/';
  }
}

// Parse the query string of a URL into a flat { name: value } map. Tolerates
// bare paths and malformed URLs.
export function queryFromUrl(url) {
  const raw = String(url || '');
  const qIndex = raw.indexOf('?');
  if (qIndex < 0) return {};
  const out = {};
  const search = raw.slice(qIndex + 1).split('#')[0];
  for (const pair of search.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const key = eq < 0 ? pair : pair.slice(0, eq);
    const value = eq < 0 ? '' : pair.slice(eq + 1);
    try {
      out[decodeURIComponent(key)] = decodeURIComponent(value.replace(/\+/g, ' '));
    } catch {
      out[key] = value;
    }
  }
  return out;
}

// ---- endpoint matching -----------------------------------------------------

export function pathPattern(path) {
  const escaped = String(path || '/')
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\\\{[^}]+\\\}/g, '[^/]+');
  return new RegExp(`^${escaped}/?$`);
}

export function matchEndpoint(endpoints, method, path) {
  return (endpoints || []).find(
    (endpoint) => endpoint.method === method && pathPattern(endpoint.path).test(path)
  );
}

// ---- object / JSON helpers -------------------------------------------------

// Dotted key paths for every value in a nested object/array.
export function objectPaths(value, prefix = '') {
  if (!value || typeof value !== 'object') return [];
  if (Array.isArray(value)) return value.flatMap((item) => objectPaths(item, prefix));
  const out = [];
  for (const [key, next] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    out.push(path);
    out.push(...objectPaths(next, path));
  }
  return out;
}

export function tryParseJson(text) {
  if (typeof text !== 'string' || !text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

// ---- cookie helpers --------------------------------------------------------

// httpClient joins multiple Set-Cookie values with "\n" (one per line). Split
// back into individual raw cookie strings.
export function splitSetCookie(value) {
  if (value == null) return [];
  return String(value)
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

// Parse a single raw Set-Cookie value into { name, value, attrs } where attrs
// is a lower-cased Map of attribute name -> value ('' for valueless flags).
export function parseCookie(raw) {
  const parts = String(raw || '').split(';');
  const [pair = ''] = parts;
  const eq = pair.indexOf('=');
  const name = (eq < 0 ? pair : pair.slice(0, eq)).trim();
  const value = eq < 0 ? '' : pair.slice(eq + 1).trim();
  const attrs = new Map();
  for (const part of parts.slice(1)) {
    const seg = part.trim();
    if (!seg) continue;
    const aeq = seg.indexOf('=');
    const aname = (aeq < 0 ? seg : seg.slice(0, aeq)).trim().toLowerCase();
    const aval = aeq < 0 ? '' : seg.slice(aeq + 1).trim();
    attrs.set(aname, aval);
  }
  return { name, value, attrs };
}

// Parse all Set-Cookie values from a (raw or lowercased) header map.
export function parseSetCookies(headers) {
  return splitSetCookie(getHeader(headers, 'set-cookie')).map(parseCookie);
}

// ---- history iteration -----------------------------------------------------

// Normalize one raw history entry into a stable record for log analyzers.
export function normalizeHistoryEntry(entry, endpoints = []) {
  const request = entry?.request || {};
  const response = entry?.response || {};
  const method = String(request.method || entry?.method || 'GET').toUpperCase();
  const url = request.url || entry?.url || '';
  const path = pathFromUrl(url);
  const status = Number(response.status ?? entry?.status ?? 0) || 0;
  return {
    method,
    url,
    path,
    query: queryFromUrl(url),
    status,
    reqHeaders: lowerHeaders(request.headers || {}),
    reqBody: request.body == null ? '' : String(request.body),
    resHeaders: lowerHeaders(response.headers || {}),
    resBody: response.body == null ? '' : String(response.body),
    isHttps: /^https:/i.test(String(url)),
    endpoint: matchEndpoint(endpoints, method, path) || null,
    raw: entry,
  };
}

// Yield normalized history records (capped) for the log analyzers.
export function eachHistory(history, endpoints, limit = 200) {
  if (!Array.isArray(history)) return [];
  return history.slice(0, limit).map((entry) => normalizeHistoryEntry(entry, endpoints));
}

// ---- de-duplication --------------------------------------------------------

// Collapse identical findings (same sev/category/title/path/evidence) so the
// same issue across many log entries or endpoints is reported once.
export function dedupeFindings(findings) {
  const seen = new Set();
  const out = [];
  for (const finding of findings) {
    const key = [finding.sev, finding.category, finding.title, finding.method, finding.path, finding.evidence].join('|');
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding);
  }
  return out;
}
