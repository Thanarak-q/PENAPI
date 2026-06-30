// Pure authentication-intelligence analyzer. Covers OWASP API2:2023 Broken Authentication.
// Spec/scheme checks derived from ctx.securitySchemes; log checks derived from ctx.records.
// Returns finding spec objects only — do NOT call makeFinding here.
// The orchestrator in static-analysis.js normalises each spec through makeFinding.

import { dedupeFindings, getHeader, tryParseJson, parseSetCookies } from './shared.js';

// ---- named regex constants ---------------------------------------------------

const RE_JWT_FIND   = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
const RE_HS_ALG     = /^hs/i;
const RE_AUTH_PATH  = /(login|signin|authenticate|token|oauth)/i;
const RE_SESSION_CK = /sess|sid|auth|jwt|token/i;
const RE_CRED_KEY   = /(password|passwd|pwd|secret|token|otp|api[_-]?key)/i;

const ONE_YEAR_SEC  = 31536000;

// ---- helpers -----------------------------------------------------------------

// Show first 2 + last 2 chars, up to 10 stars. Never expose full credential.
function mask(s) {
  const str = String(s || '');
  if (str.length <= 4) return '***';
  return str.slice(0, 2) + '*'.repeat(Math.min(str.length - 4, 10)) + str.slice(-2);
}

// Base64url decode to binary string. Works in browser (atob) and Node.js (Buffer).
const dec = s => {
  try {
    const t = String(s).replace(/-/g, '+').replace(/_/g, '/');
    const pad = t.length % 4 ? '='.repeat(4 - (t.length % 4)) : '';
    return typeof atob === 'function'
      ? atob(t + pad)
      : Buffer.from(t + pad, 'base64').toString('binary');
  } catch { return ''; }
};

// Find all JWT strings in arbitrary text.
function findJwts(text) {
  if (!text) return [];
  return [...String(text).matchAll(new RegExp(RE_JWT_FIND.source, 'g'))].map(m => m[0]);
}

// Decode a JWT's header and payload into parsed JSON objects (either may be null).
function decodeJwt(token) {
  const parts = String(token || '').split('.');
  if (parts.length < 3) return null;
  return {
    header: tryParseJson(dec(parts[0])),
    payload: tryParseJson(dec(parts[1])),
  };
}

// Derive the canonical endpoint object from a record.
function endpointOf(record) {
  return record.endpoint || {
    method: record.method,
    path: record.path,
    id: `${record.method} ${record.path}`,
  };
}

// Build a finding spec for this module. Defaults to a log-derived source; the
// spec-level scheme checks override this to 'spec' below.
function authSpec(sev, title, endpoint, evidence, action, cwe, confidence = 'firm') {
  return { sev, category: 'security', title, endpoint, evidence, action, owasp: 'API2:2023', cwe, confidence, source: 'history' };
}

// ---- scheme checks (1–3): spec-level, endpoint: null ------------------------

function schemeFindings(securitySchemes) {
  const out = [];
  if (!securitySchemes || typeof securitySchemes !== 'object') return out;

  for (const [name, scheme] of Object.entries(securitySchemes)) {
    if (!scheme) continue;
    const schemeLower = String(scheme.scheme || '').toLowerCase();

    // 1. HTTP Basic
    if (scheme.type === 'http' && schemeLower === 'basic') {
      out.push(authSpec(
        'medium',
        'HTTP Basic authentication scheme in use',
        null,
        `scheme: ${name}`,
        'HTTP Basic sends base64(user:pass) which is trivially reversible. Prefer short-lived tokens with TLS.',
        'CWE-522',
      ));
    }

    // 2. API key in cookie
    if (scheme.type === 'apiKey' && scheme.in === 'cookie') {
      out.push(authSpec(
        'low',
        'API key carried in a cookie',
        null,
        `scheme: ${name}`,
        'API keys in cookies are vulnerable to CSRF and XSS theft; use the Authorization header instead.',
        'CWE-522',
      ));
    }

    // 3. Bearer without bearerFormat
    if (scheme.type === 'http' && schemeLower === 'bearer' && !scheme.bearerFormat) {
      out.push(authSpec(
        'info',
        'Bearer scheme without declared bearerFormat',
        null,
        `scheme: ${name}`,
        'Declare bearerFormat (e.g. JWT) so tooling and consumers understand the token format.',
        'CWE-1059',
        'tentative',
      ));
    }
  }

  return out;
}

// ---- JWT analysis for a single token (check 5) --------------------------------

function jwtFindings(token, record) {
  const decoded = decodeJwt(token);
  if (!decoded || !decoded.header) return [];

  const out = [];
  const ep = endpointOf(record);
  const { header, payload } = decoded;
  const algRaw = String(header.alg || '');
  const algLower = algRaw.toLowerCase();

  // alg=none — allows forged unsigned tokens
  if (algLower === 'none') {
    out.push(authSpec(
      'high',
      'JWT with alg=none observed',
      ep,
      'alg=none',
      'The alg=none bypass allows forged tokens. Reject alg=none server-side unconditionally.',
      'CWE-347',
    ));
  }

  // Symmetric HS* (but not the special 'none' token)
  if (algLower !== 'none' && RE_HS_ALG.test(algLower)) {
    out.push(authSpec(
      'low',
      'JWT uses symmetric signing (HS*)',
      ep,
      `alg=${algRaw.toUpperCase()}`,
      'HS* keys must be strong and secret. Guard against RS256→HS256 alg-confusion attacks; validate alg server-side.',
      'CWE-347',
      'tentative',
    ));
  }

  if (payload && typeof payload === 'object') {
    // No exp claim
    if (!('exp' in payload)) {
      out.push(authSpec(
        'medium',
        'JWT without expiry (exp) claim',
        ep,
        'no exp claim',
        'Always include an exp claim. Tokens without expiry remain valid indefinitely.',
        'CWE-613',
      ));
    }

    // Lifetime > 1 year
    if ('exp' in payload && 'iat' in payload) {
      const ttl = Number(payload.exp) - Number(payload.iat);
      if (ttl > ONE_YEAR_SEC) {
        const days = Math.round(ttl / 86400);
        out.push(authSpec(
          'low',
          'JWT lifetime exceeds 1 year',
          ep,
          `ttl≈${days}d`,
          'Reduce JWT lifetime to hours or days; use refresh tokens for long-lived sessions.',
          'CWE-613',
        ));
      }
    }
  }

  return out;
}

// ---- log-based checks (4–7) for a single record ----------------------------

function scanRecord(record, out) {
  const ep = endpointOf(record);

  // 4. HTTP Basic credentials in request
  const authHeader = String(getHeader(record.reqHeaders, 'authorization') || '');
  if (authHeader.startsWith('Basic ')) {
    out.push(authSpec(
      'medium',
      'HTTP Basic credentials sent in request',
      ep,
      'Authorization: Basic ****',
      'Replace HTTP Basic with token-based authentication (e.g. Bearer/JWT).',
      'CWE-522',
    ));
  }

  // 5. JWT analysis — scan auth header, request body, response body
  const seenInRecord = new Set();
  for (const text of [authHeader, record.reqBody, record.resBody]) {
    for (const token of findJwts(text)) {
      const key = token.slice(0, 40);
      if (seenInRecord.has(key)) continue;
      seenInRecord.add(key);
      out.push(...jwtFindings(token, record));
    }
  }

  // 6. Credentials submitted over plaintext HTTP
  const url = String(record.url || '');
  if (url.startsWith('http://')) {
    const matchedKey = credentialKeyIn(record);
    if (matchedKey) {
      out.push(authSpec(
        'high',
        'Credentials submitted over plaintext HTTP',
        ep,
        matchedKey,
        'Use HTTPS exclusively for all endpoints that accept credentials.',
        'CWE-319',
      ));
    }
  }

  // 7. Session cookie without HttpOnly on auth-flow response
  if (RE_AUTH_PATH.test(record.path) && record.status >= 200 && record.status < 300) {
    for (const cookie of parseSetCookies(record.resHeaders)) {
      if (RE_SESSION_CK.test(cookie.name) && !cookie.attrs.has('httponly')) {
        out.push(authSpec(
          'medium',
          'Session cookie set without HttpOnly on auth response',
          ep,
          cookie.name,
          'Set the HttpOnly flag on session cookies to block JavaScript access.',
          'CWE-1004',
        ));
      }
    }
  }
}

// Extract the first credential-like key name from query params or request body.
// Returns the matched key name string, or null if none found.
function credentialKeyIn(record) {
  const queryMatch = Object.keys(record.query || {}).find(k => RE_CRED_KEY.test(k));
  if (queryMatch) return queryMatch;

  if (!record.reqBody) return null;

  const bodyObj = tryParseJson(record.reqBody);
  if (bodyObj && typeof bodyObj === 'object' && !Array.isArray(bodyObj)) {
    const jsonMatch = Object.keys(bodyObj).find(k => RE_CRED_KEY.test(k));
    if (jsonMatch) return jsonMatch;
  }

  // Fall back to raw string scan (URL-encoded bodies, etc.)
  const m = RE_CRED_KEY.exec(record.reqBody);
  return m ? m[0] : null;
}

// ---- main export -------------------------------------------------------------

export function analyzeAuthIntelligence(ctx) {
  const records = Array.isArray(ctx.records) ? ctx.records : [];
  const securitySchemes = ctx.securitySchemes || {};
  const out = [];

  // Scheme checks are spec-derived; mark their source accordingly.
  out.push(...schemeFindings(securitySchemes).map((f) => ({ ...f, source: 'spec' })));

  for (const record of records) {
    scanRecord(record, out);
  }

  return dedupeFindings(out);
}
