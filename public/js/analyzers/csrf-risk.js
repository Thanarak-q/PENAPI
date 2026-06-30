// Pure CSRF-risk analyzer. Covers OWASP API8:2023 Security Misconfiguration / CWE-352.
// Log-driven: uses ctx.records. Returns finding spec objects only — do NOT call makeFinding here.
// The orchestrator in static-analysis.js normalises each spec through makeFinding.

import { MUTATING, dedupeFindings, getHeader, tryParseJson } from './shared.js';

// ---- named regex constants ---------------------------------------------------

const RE_CSRF_FIELD = /(csrf|xsrf|_token|authenticity_token|anti.?forgery)/i;
const RE_SIMPLE_CT  = /^(application\/x-www-form-urlencoded|multipart\/form-data|text\/plain)/i;

const CSRF_TOKEN_HEADERS = ['x-csrf-token', 'x-xsrf-token', 'csrf-token', 'x-csrftoken'];

// ---- helpers -----------------------------------------------------------------

function endpointOf(record) {
  return record.endpoint || {
    method: record.method,
    path: record.path,
    id: `${record.method} ${record.path}`,
  };
}

// Returns true when the request carries a cookie but no header-based token that
// would prevent cross-site forgery. Bearer/api-key headers are not automatically
// attached by browsers, so their presence means the request is not CSRF-able.
function isCookieAuthed(record) {
  if (!getHeader(record.reqHeaders, 'cookie')) return false;
  if (getHeader(record.reqHeaders, 'authorization')) return false;
  if (getHeader(record.reqHeaders, 'x-api-key')) return false;
  if (getHeader(record.reqHeaders, 'api-key')) return false;
  if (getHeader(record.reqHeaders, 'x-auth-token')) return false;
  return true;
}

// Returns 'token' if a real CSRF token is detected (request headers, body field
// names, or query param names); 'xrw' if only X-Requested-With is present; null
// if no anti-CSRF defense is found at all.
function csrfSignal(record) {
  for (const name of CSRF_TOKEN_HEADERS) {
    if (getHeader(record.reqHeaders, name)) return 'token';
  }

  const bodyObj = tryParseJson(record.reqBody);
  if (bodyObj && typeof bodyObj === 'object' && !Array.isArray(bodyObj)) {
    if (Object.keys(bodyObj).some(k => RE_CSRF_FIELD.test(k))) return 'token';
  }

  if (record.query && Object.keys(record.query).some(k => RE_CSRF_FIELD.test(k))) return 'token';

  // Raw body scan covers URL-encoded and other non-JSON formats.
  if (record.reqBody && RE_CSRF_FIELD.test(record.reqBody)) return 'token';

  if (getHeader(record.reqHeaders, 'x-requested-with')) return 'xrw';

  return null;
}

// Returns true for content-types that do not trigger a CORS preflight, or when
// the content-type is absent. These types allow cross-site form submission.
function isSimpleContentType(ct) {
  if (!ct) return true;
  return RE_SIMPLE_CT.test(ct);
}

function csrfSpec(sev, title, endpoint, evidence, action, confidence = 'firm') {
  return {
    sev,
    category: 'security',
    title,
    endpoint,
    evidence,
    action,
    owasp: 'API8:2023',
    cwe: 'CWE-352',
    confidence,
  };
}

// ---- per-record scan ---------------------------------------------------------

function scanRecord(record, out) {
  if (!MUTATING.has(record.method)) return;
  if (!isCookieAuthed(record)) return;

  const ep = endpointOf(record);
  const signal = csrfSignal(record);

  if (signal === 'token') return;

  if (signal === 'xrw') {
    out.push(csrfSpec(
      'low',
      'CSRF defense relies only on X-Requested-With',
      ep,
      `${record.method} ${record.path} — only X-Requested-With present`,
      'X-Requested-With can be insufficient depending on CORS config — prefer a synchronizer token or SameSite cookies.',
      'tentative',
    ));
    return;
  }

  // signal === null: no anti-CSRF defense detected
  const ct = getHeader(record.reqHeaders, 'content-type') || '';
  const ctLabel = ct || '(no content-type)';

  if (isSimpleContentType(ct)) {
    out.push(csrfSpec(
      'medium',
      'CSRF-able simple request (no preflight content-type)',
      ep,
      `${record.method} ${record.path} (${ctLabel})`,
      'Simple content-types (form-urlencoded, multipart, text/plain, or absent) allow cross-site form submission without a preflight — add a per-request anti-CSRF token or enforce SameSite=strict cookies.',
    ));
  } else {
    out.push(csrfSpec(
      'medium',
      'State-changing request authenticated by cookie without CSRF token',
      ep,
      `${record.method} ${record.path} (${ctLabel})`,
      'Cookie-based auth on a state-changing endpoint with no CSRF token is CSRF-able — require a per-request anti-CSRF token or SameSite=strict cookies and verify Origin.',
    ));
  }
}

// ---- main export -------------------------------------------------------------

export function analyzeCsrfRisk(ctx) {
  const records = Array.isArray(ctx.records) ? ctx.records : [];
  const out = [];

  for (const record of records) {
    scanRecord(record, out);
  }

  return dedupeFindings(out);
}
