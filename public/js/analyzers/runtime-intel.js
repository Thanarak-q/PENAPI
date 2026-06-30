// Pure runtime-intelligence analyzer. LOG-DRIVEN — only scans ctx.records.
// Covers observed runtime behavior: reflected input, open redirect, GraphQL
// introspection, enumerable numeric IDs, and verbose error diagnostics.
// Returns finding spec objects; do NOT call makeFinding here.
// The orchestrator in static-analysis.js normalises them.

import { dedupeFindings, tryParseJson } from './shared.js';

// ---- named regex constants ---------------------------------------------------

const RE_REDIRECT_PARAM = /(redirect|return|returnurl|next|url|continue|callback|dest|destination|to|goto|target)/i;
const RE_GRAPHQL_PATH   = /graphql|graphiql/i;
const RE_NUMERIC_TAIL   = /\/(\d{1,10})\/?$/;
const RE_DIAG_KEY       = /(stack|stacktrace|exception|trace|debug|sql|query|file|line|errno|cause)/i;

const MAX_BODY   = 50000;
const MAX_EV_LEN = 60;
const MAX_ID     = 100000;

// ---- utilities ---------------------------------------------------------------

// Cap body text to first MAX_BODY chars before scanning.
function cap(text) {
  return typeof text === 'string' ? text.slice(0, MAX_BODY) : '';
}

// Derive the canonical endpoint object from a record.
function endpointOf(record) {
  return record.endpoint || {
    method: record.method,
    path:   record.path,
    id:     `${record.method} ${record.path}`,
  };
}

// Truncate to at most n chars, appending an ellipsis when cut.
function truncate(s, n = MAX_EV_LEN) {
  const str = String(s || '');
  return str.length <= n ? str : str.slice(0, n - 1) + '…';
}

// Collect all { name, val } string-leaf pairs from a nested object/array.
// name is the dotted key path (e.g. 'address.city' or '[0].name').
function collectBodyCandidates(obj, prefix, out) {
  if (obj === null || obj === undefined || typeof obj !== 'object') return;
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      collectBodyCandidates(obj[i], prefix ? `${prefix}[${i}]` : `[${i}]`, out);
    }
    return;
  }
  for (const [key, val] of Object.entries(obj)) {
    const name = prefix ? `${prefix}.${key}` : key;
    if (typeof val === 'string') {
      out.push({ name, val });
    } else if (val && typeof val === 'object') {
      collectBodyCandidates(val, name, out);
    }
  }
}

// Walk an object recursively to collect keys matching re (up to depth 10).
function diagKeys(obj, re, out, depth) {
  if (depth > 10 || !obj || typeof obj !== 'object') return;
  if (Array.isArray(obj)) {
    for (const item of obj) diagKeys(item, re, out, depth + 1);
    return;
  }
  for (const [key, val] of Object.entries(obj)) {
    if (re.test(key) && !out.includes(key)) out.push(key);
    if (val && typeof val === 'object') diagKeys(val, re, out, depth + 1);
  }
}

// ---- per-check helpers -------------------------------------------------------

// Check 1: reflected request input in response body (potential XSS/HTML injection).
function reflectedFinding(record) {
  const st = record.status;
  if (!((st >= 200 && st < 300) || (st >= 400 && st < 500))) return null;
  const body = cap(record.resBody);
  if (!body) return null;

  const candidates = [];

  // (a) query param values
  for (const [name, val] of Object.entries(record.query || {})) {
    if (typeof val === 'string') candidates.push({ name, val });
  }

  // (b) string values from parsed request body
  const bodyObj = tryParseJson(record.reqBody);
  if (bodyObj && typeof bodyObj === 'object') {
    collectBodyCandidates(bodyObj, '', candidates);
  }

  // Check each candidate; stop after the first reflection found.
  for (const { name, val } of candidates) {
    if (val.length < 6) continue;
    if (/^\d+$/.test(val)) continue;
    if (val === 'true' || val === 'false' || val === 'null') continue;
    if (!body.includes(val)) continue;

    const idx = body.indexOf(val);
    const snippet = truncate(body.slice(idx, idx + MAX_EV_LEN));
    return {
      sev: 'low',
      category: 'injection',
      title: 'Request input reflected in response body',
      endpoint: endpointOf(record),
      evidence: `${name}: ${snippet}`,
      action: 'Reflected input is a candidate for XSS/HTML injection — verify output encoding and content-type.',
      owasp: 'API8:2023',
      cwe: 'CWE-79',
      confidence: 'tentative',
    };
  }

  return null;
}

// Check 2: open redirect — user-controlled param reflected in Location header.
function redirectFinding(record) {
  if (record.status < 300 || record.status > 399) return null;
  const location = record.resHeaders['location'];
  if (!location) return null;
  const locStr = String(location);

  for (const [name, val] of Object.entries(record.query || {})) {
    if (!RE_REDIRECT_PARAM.test(name)) continue;
    if (typeof val !== 'string' || !val) continue;
    if (!locStr.includes(val)) continue;

    return {
      sev: 'medium',
      category: 'injection',
      title: 'Open redirect: request parameter reflected in Location',
      endpoint: endpointOf(record),
      evidence: truncate(`${name} → ${locStr}`),
      action: 'A user-controlled value flows into the redirect target — test external-host redirection and javascript: payloads.',
      owasp: 'API7:2023',
      cwe: 'CWE-601',
      confidence: 'firm',
    };
  }

  return null;
}

// Check 3: GraphQL introspection enabled.
function graphqlFinding(record) {
  const body = cap(record.resBody);
  if (!body) return null;
  if (!body.includes('"__schema"') && !body.includes('"__type"')) return null;

  const pathOk = RE_GRAPHQL_PATH.test(record.path);
  const reqOk  = typeof record.reqBody === 'string' && record.reqBody.includes('__schema');
  if (!pathOk && !reqOk) return null;

  return {
    sev: 'medium',
    category: 'config',
    title: 'GraphQL introspection appears enabled',
    endpoint: endpointOf(record),
    evidence: 'response exposes __schema/__type',
    action: 'Disable introspection in production or restrict it to trusted roles.',
    owasp: 'API8:2023',
    cwe: 'CWE-200',
    confidence: 'firm',
  };
}

// Check 4: sequential/numeric object identifier observed.
// seenTemplates prevents emitting more than one finding per path template.
function numericIdFinding(record, seenTemplates) {
  if (record.method !== 'GET') return null;
  if (record.status < 200 || record.status >= 300) return null;
  const m = RE_NUMERIC_TAIL.exec(record.path);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  if (n > MAX_ID) return null;

  // Build a stable path template for deduplication.
  const template = record.path.replace(RE_NUMERIC_TAIL, '/{id}');
  if (seenTemplates.has(template)) return null;
  seenTemplates.add(template);

  return {
    sev: 'low',
    category: 'idor',
    title: 'Sequential/numeric object identifier observed',
    endpoint: endpointOf(record),
    evidence: `id=${n} at ${template}`,
    action: 'Small integer object ids are enumerable — test BOLA by iterating ids across identities.',
    owasp: 'API1:2023',
    cwe: 'CWE-639',
    confidence: 'tentative',
  };
}

// Check 5: verbose JSON error structure with internal diagnostic fields.
function diagFinding(record) {
  if (record.status < 400) return null;
  const obj = tryParseJson(cap(record.resBody));
  if (!obj || typeof obj !== 'object') return null;

  const matched = [];
  diagKeys(obj, RE_DIAG_KEY, matched, 0);
  if (!matched.length) return null;

  const top3  = matched.slice(0, 3).join(', ');
  const extra = matched.length > 3 ? ` (+${matched.length - 3} more)` : '';

  return {
    sev: 'low',
    category: 'config',
    title: 'Error response exposes internal diagnostic fields',
    endpoint: endpointOf(record),
    evidence: `Fields: ${top3}${extra}`,
    action: 'Return generic error messages; strip stack/SQL/file diagnostics from production responses.',
    owasp: 'API8:2023',
    cwe: 'CWE-209',
    confidence: 'firm',
  };
}

// ---- main export -------------------------------------------------------------

export function analyzeRuntimeIntel(ctx) {
  const records = Array.isArray(ctx.records) ? ctx.records : [];
  const findings = [];
  const seenIdTemplates = new Set();

  for (const record of records) {
    const f1 = reflectedFinding(record);
    if (f1) findings.push(f1);

    const f2 = redirectFinding(record);
    if (f2) findings.push(f2);

    const f3 = graphqlFinding(record);
    if (f3) findings.push(f3);

    const f4 = numericIdFinding(record, seenIdTemplates);
    if (f4) findings.push(f4);

    const f5 = diagFinding(record);
    if (f5) findings.push(f5);
  }

  return dedupeFindings(findings);
}
