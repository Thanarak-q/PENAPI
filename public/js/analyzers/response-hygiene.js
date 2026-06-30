// Log-driven analyzer: API8:2023 Security Misconfiguration checks derived from
// saved HTTP history. Produces finding specs (plain objects); the orchestrator
// normalizes them via makeFinding. No network calls, no side effects.
//
// Recon-aggregated counterpart of public/js/analyze.js: analyze.js scores ONE
// live response in the Response panel, while this walks the entire saved request
// log, dedupes, attaches OWASP-API/CWE metadata, and links each finding to its
// endpoint for the Attack Surface view.

import { parseSetCookies, dedupeFindings } from './shared.js';

// ---- named regex constants --------------------------------------------------

const RE_STACK_PYTHON  = /Traceback \(most recent call last\)/;
const RE_STACK_JS_JAVA = /\bat [\w$.]+\s*\([^)]*:\d+:\d+\)/;
const RE_SQL_ERROR     = /SQLSTATE\[|\bORA-\d{5}\b|SQLException|System\.[A-Za-z.]+Exception/;
const RE_PHP_ERROR     = /<b>(Warning|Fatal error|Notice)<\/b>/i;
const RE_FILE_PATH     = /\/(home|var|usr|opt|app)\/[\w./-]+\.(js|ts|py|rb|php|java):\d+/;
const RE_AUTH_PATH     = /(login|signin|authenticate|token|otp|verify|2fa|mfa|reset|forgot|password|register|signup)/i;

const FINGERPRINT_HEADERS = [
  'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version',
  'x-runtime', 'x-generator', 'x-drupal-cache',
];

const RATE_LIMIT_HEADERS = [
  'x-ratelimit-limit', 'ratelimit-limit', 'x-rate-limit-limit', 'retry-after',
];

const OWASP    = 'API8:2023';
const CATEGORY = 'config';

// ---- helpers ----------------------------------------------------------------

function endpointFor(record) {
  return record.endpoint || {
    method: record.method,
    path: record.path,
    id: record.method + ' ' + record.path,
  };
}

function spec(sev, title, ep, evidence, action, cwe, confidence = 'firm') {
  return { sev, category: CATEGORY, title, endpoint: ep, evidence, action, owasp: OWASP, cwe, confidence };
}

function trunc(str, len) {
  const s = String(str || '').replace(/[\r\n]+/g, ' ');
  return s.length > len ? s.slice(0, len) + '…' : s;
}

function isSameOrigin(url, origin) {
  try {
    return new URL(url).origin === new URL(origin).origin;
  } catch {
    return false;
  }
}

// ---- per-record checks ------------------------------------------------------

function checkCors(record, ep, findings) {
  const acao = record.resHeaders['access-control-allow-origin'];
  if (!acao) return;

  const acac = (record.resHeaders['access-control-allow-credentials'] || '').toLowerCase();
  const withCreds = acac === 'true';
  const reqOrigin = record.reqHeaders['origin'];

  if (acao === '*') {
    if (withCreds) {
      findings.push(spec('high', 'CORS allows credentials with permissive origin', ep,
        'ACAO: *, ACAC: true',
        'Remove the wildcard ACAO and specify an explicit allowed origin.',
        'CWE-942'));
    } else {
      findings.push(spec('medium', 'CORS allows any origin', ep,
        'access-control-allow-origin: *',
        'Restrict Access-Control-Allow-Origin to a trusted explicit origin.',
        'CWE-942'));
    }
    return;
  }

  if (reqOrigin && acao === reqOrigin && !isSameOrigin(record.url, reqOrigin)) {
    if (withCreds) {
      findings.push(spec('high', 'CORS allows credentials with permissive origin', ep,
        trunc('ACAO reflects ' + reqOrigin + ', ACAC: true', 120),
        'Validate the request Origin against a strict allowlist before reflecting it.',
        'CWE-942'));
    } else {
      findings.push(spec('high', 'CORS reflects arbitrary origin', ep,
        trunc('ACAO reflects ' + reqOrigin, 120),
        'Validate the request Origin against a strict allowlist before reflecting it.',
        'CWE-942'));
    }
  }
}

function checkSecurityHeaders(record, ep, findings) {
  const h = record.resHeaders;

  if (record.isHttps && !h['strict-transport-security']) {
    findings.push(spec('medium', 'HSTS not set over HTTPS', ep,
      'strict-transport-security',
      'Add Strict-Transport-Security: max-age=31536000; includeSubDomains.',
      'CWE-319'));
  }

  if (!h['x-content-type-options']) {
    findings.push(spec('low', 'Missing X-Content-Type-Options header', ep,
      'x-content-type-options',
      'Set X-Content-Type-Options: nosniff on all responses.',
      'CWE-693'));
  }

  const hasCsp            = !!h['content-security-policy'];
  const cspHasFrameAnc    = hasCsp && /frame-ancestors/i.test(h['content-security-policy']);
  const hasXfo            = !!h['x-frame-options'];
  if (!hasXfo && !cspHasFrameAnc) {
    findings.push(spec('low', 'Clickjacking protection missing', ep,
      'x-frame-options',
      'Set X-Frame-Options: DENY or add frame-ancestors to the Content-Security-Policy.',
      'CWE-1021'));
  }

  if (!hasCsp) {
    findings.push(spec('info', 'No Content-Security-Policy', ep,
      'content-security-policy',
      'Define a Content-Security-Policy response header to restrict resource loading.',
      'CWE-693', 'tentative'));
  }

  if (!h['referrer-policy']) {
    findings.push(spec('info', 'Missing Referrer-Policy header', ep,
      'referrer-policy',
      'Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin.',
      'CWE-693', 'tentative'));
  }
}

function checkCookieFlags(record, ep, findings) {
  const cookies = parseSetCookies(record.resHeaders);
  for (const cookie of cookies) {
    const name = cookie.name || '(unnamed)';
    if (!cookie.attrs.has('httponly')) {
      findings.push(spec('medium', 'Cookie missing HttpOnly', ep,
        name,
        'Set the HttpOnly flag on all session and authentication cookies.',
        'CWE-1004'));
    }
    if (record.isHttps && !cookie.attrs.has('secure')) {
      findings.push(spec('medium', 'Cookie missing Secure flag', ep,
        name,
        'Set the Secure flag on cookies sent over HTTPS connections.',
        'CWE-614'));
    }
    if (!cookie.attrs.has('samesite')) {
      findings.push(spec('low', 'Cookie missing SameSite', ep,
        name,
        'Set SameSite=Lax or SameSite=Strict to mitigate CSRF attacks.',
        'CWE-1275'));
    }
  }
}

function checkFingerprint(record, ep, findings) {
  for (const hdr of FINGERPRINT_HEADERS) {
    const val = record.resHeaders[hdr];
    if (!val) continue;
    findings.push(spec('low', 'Technology fingerprint disclosed in response header', ep,
      trunc(hdr + ': ' + val, 80),
      'Remove or genericise the ' + hdr + ' header to reduce attack surface.',
      'CWE-200'));
  }
}

function firstStackMatch(body) {
  const patterns = [RE_STACK_PYTHON, RE_STACK_JS_JAVA, RE_SQL_ERROR, RE_PHP_ERROR, RE_FILE_PATH];
  for (const re of patterns) {
    const m = re.exec(body);
    if (m) return m[0];
  }
  return null;
}

function checkStackTrace(record, ep, findings) {
  if (!record.resBody) return;
  const match = firstStackMatch(record.resBody);
  if (!match) return;
  findings.push(spec('medium', 'Verbose error / stack trace in response body', ep,
    trunc(match, 120),
    'Return a generic error message to clients; log full details server-side only.',
    'CWE-209'));
}

function checkContentType(record, ep, findings) {
  const ct   = record.resHeaders['content-type'] || '';
  const body = (record.resBody || '').trim();
  const looksJson = body.startsWith('{') || body.startsWith('[');

  if (looksJson && !ct.includes('json')) {
    findings.push(spec('low', 'JSON body served with non-JSON Content-Type', ep,
      ct || '(none)',
      'Set Content-Type: application/json for all JSON response bodies.',
      'CWE-436'));
  }

  if (record.status >= 200 && record.status < 300 && ct.includes('text/html')) {
    const isApi = record.path.includes('/api/') || !!record.endpoint;
    if (isApi) {
      findings.push(spec('info', 'API endpoint returned HTML', ep,
        record.method + ' ' + record.path,
        'API endpoints should return structured data (JSON), not HTML pages.',
        'CWE-436', 'tentative'));
    }
  }
}

function checkRateLimit(record, ep, findings) {
  if (!RE_AUTH_PATH.test(record.path)) return;
  const hasRateLimit = RATE_LIMIT_HEADERS.some((h) => record.resHeaders[h]);
  if (hasRateLimit) return;
  findings.push(spec('low', 'No rate-limit headers on authentication response', ep,
    record.path,
    'Implement rate limiting on authentication endpoints and expose X-RateLimit-* headers.',
    'CWE-770', 'tentative'));
}

// ---- public API -------------------------------------------------------------

export function analyzeResponseHygiene(ctx) {
  const { records } = ctx;
  if (!records || records.length === 0) return [];

  const findings = [];
  for (const record of records) {
    if (!record.status) continue;

    const ep = endpointFor(record);

    checkCors(record, ep, findings);

    if (record.status >= 200 && record.status <= 399) {
      checkSecurityHeaders(record, ep, findings);
    }

    checkCookieFlags(record, ep, findings);
    checkFingerprint(record, ep, findings);

    if (record.status >= 400) {
      checkStackTrace(record, ep, findings);
    }

    checkContentType(record, ep, findings);
    checkRateLimit(record, ep, findings);
  }

  return dedupeFindings(findings);
}
