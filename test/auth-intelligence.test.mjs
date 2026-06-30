import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeAuthIntelligence } from '../public/js/analyzers/auth-intelligence.js';
import { eachHistory } from '../public/js/analyzers/shared.js';

// ---- helpers -----------------------------------------------------------------

// base64url-encode a JSON value (ASCII-safe objects only).
const b64u = o =>
  Buffer.from(JSON.stringify(o)).toString('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

// Build a syntactically valid JWT from header and payload objects.
const makeJwt = (h, p) => `${b64u(h)}.${b64u(p)}.sig`;

function entry({
  url = 'https://api.example.test/api',
  method = 'GET',
  reqHeaders = {},
  reqBody = '',
  resHeaders = {},
  resBody = '',
  status = 200,
} = {}) {
  return {
    request: { method, url, headers: reqHeaders, body: reqBody },
    response: { status, headers: resHeaders, body: resBody },
  };
}

function makeCtx({ entries = [], securitySchemes = {} } = {}) {
  return {
    spec: {},
    endpoints: [],
    securitySchemes,
    history: entries,
    records: eachHistory(entries, []),
  };
}

function titles(findings) {
  return findings.map(f => f.title);
}

// ---- scheme checks -----------------------------------------------------------

test('HTTP Basic scheme emits medium finding with correct metadata', () => {
  const ctx = makeCtx({
    securitySchemes: { basicAuth: { type: 'http', scheme: 'basic' } },
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(titles(findings).includes('HTTP Basic authentication scheme in use'), 'title expected');
  const f = findings.find(x => x.title === 'HTTP Basic authentication scheme in use');
  assert.equal(f.sev, 'medium');
  assert.equal(f.category, 'security');
  assert.equal(f.cwe, 'CWE-522');
  assert.equal(f.owasp, 'API2:2023');
  assert.equal(f.endpoint, null, 'spec-level findings have endpoint: null');
});

test('apiKey scheme in cookie emits low finding', () => {
  const ctx = makeCtx({
    securitySchemes: { cookieKey: { type: 'apiKey', in: 'cookie', name: 'X-API-Key' } },
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(titles(findings).includes('API key carried in a cookie'), 'title expected');
  const f = findings.find(x => x.title === 'API key carried in a cookie');
  assert.equal(f.sev, 'low');
  assert.equal(f.cwe, 'CWE-522');
  assert.equal(f.endpoint, null);
});

test('Bearer scheme without bearerFormat emits info/tentative finding', () => {
  const ctx = makeCtx({
    securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } },
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(titles(findings).includes('Bearer scheme without declared bearerFormat'), 'title expected');
  const f = findings.find(x => x.title === 'Bearer scheme without declared bearerFormat');
  assert.equal(f.sev, 'info');
  assert.equal(f.cwe, 'CWE-1059');
  assert.equal(f.confidence, 'tentative');
  assert.equal(f.endpoint, null);
});

test('Bearer scheme WITH bearerFormat does NOT emit bearerFormat finding', () => {
  const ctx = makeCtx({
    securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } },
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(
    !titles(findings).includes('Bearer scheme without declared bearerFormat'),
    'bearerFormat present — finding must not fire',
  );
});

// ---- log checks: Basic auth in request header --------------------------------

test('Basic auth header in request emits medium finding; raw credential not in evidence', () => {
  // dXNlcjpwYXNz = base64("user:pass")
  const ctx = makeCtx({
    entries: [
      entry({ reqHeaders: { Authorization: 'Basic dXNlcjpwYXNz' } }),
    ],
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(titles(findings).includes('HTTP Basic credentials sent in request'), 'title expected');
  const f = findings.find(x => x.title === 'HTTP Basic credentials sent in request');
  assert.equal(f.sev, 'medium');
  assert.equal(f.cwe, 'CWE-522');
  assert.equal(f.confidence, 'firm');
  assert.ok(!f.evidence.includes('dXNlcjpwYXNz'), 'raw base64 must not appear in evidence');
  assert.ok(!f.evidence.includes('user:pass'), 'decoded creds must not appear in evidence');
});

// ---- log checks: JWT analysis -----------------------------------------------

test('JWT with alg=none emits high/firm finding', () => {
  const jwt = makeJwt({ alg: 'none', typ: 'JWT' }, { sub: 'user1' });
  const ctx = makeCtx({
    entries: [
      entry({ reqHeaders: { Authorization: `Bearer ${jwt}` } }),
    ],
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(titles(findings).includes('JWT with alg=none observed'), 'title expected');
  const f = findings.find(x => x.title === 'JWT with alg=none observed');
  assert.equal(f.sev, 'high');
  assert.equal(f.cwe, 'CWE-347');
  assert.equal(f.confidence, 'firm');
  assert.equal(f.evidence, 'alg=none');
  assert.ok(!f.evidence.includes(jwt), 'raw JWT must not appear in evidence');
});

test('JWT with HS256 emits low/tentative symmetric-signing finding', () => {
  const iat = 1700000000;
  const jwt = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'user1', iat, exp: iat + 3600 });
  const ctx = makeCtx({
    entries: [
      entry({ reqHeaders: { Authorization: `Bearer ${jwt}` } }),
    ],
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(titles(findings).includes('JWT uses symmetric signing (HS*)'), 'title expected');
  const f = findings.find(x => x.title === 'JWT uses symmetric signing (HS*)');
  assert.equal(f.sev, 'low');
  assert.equal(f.cwe, 'CWE-347');
  assert.equal(f.confidence, 'tentative');
  assert.ok(f.evidence.includes('HS256'), 'evidence should name the algorithm');
  assert.ok(!f.evidence.includes(jwt), 'raw JWT must not appear in evidence');
});

test('JWT missing exp claim emits medium/firm finding', () => {
  const jwt = makeJwt({ alg: 'RS256', typ: 'JWT' }, { sub: 'user1' }); // no exp
  const ctx = makeCtx({
    entries: [
      entry({ reqHeaders: { Authorization: `Bearer ${jwt}` } }),
    ],
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(titles(findings).includes('JWT without expiry (exp) claim'), 'title expected');
  const f = findings.find(x => x.title === 'JWT without expiry (exp) claim');
  assert.equal(f.sev, 'medium');
  assert.equal(f.cwe, 'CWE-613');
  assert.equal(f.confidence, 'firm');
  assert.equal(f.evidence, 'no exp claim');
  assert.ok(!f.evidence.includes(jwt), 'raw JWT must not appear in evidence');
});

test('JWT with lifetime > 1 year emits low finding with day count in evidence', () => {
  const iat = 1000000000;
  const exp = iat + 2 * 365 * 86400; // 2 years
  const jwt = makeJwt({ alg: 'RS256', typ: 'JWT' }, { sub: 'user1', iat, exp });
  const ctx = makeCtx({
    entries: [
      entry({ reqHeaders: { Authorization: `Bearer ${jwt}` } }),
    ],
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(titles(findings).includes('JWT lifetime exceeds 1 year'), 'title expected');
  const f = findings.find(x => x.title === 'JWT lifetime exceeds 1 year');
  assert.equal(f.sev, 'low');
  assert.equal(f.cwe, 'CWE-613');
  assert.equal(f.confidence, 'firm');
  assert.ok(f.evidence.includes('d'), 'evidence should contain day-count notation');
  assert.ok(!f.evidence.includes(jwt), 'raw JWT must not appear in evidence');
});

// ---- log checks: credentials over plaintext HTTP ----------------------------

test('credentials in request body over HTTP emits high finding; value not in evidence', () => {
  const ctx = makeCtx({
    entries: [
      entry({
        url: 'http://api.example.test/login',
        method: 'POST',
        reqBody: JSON.stringify({ username: 'alice', password: 'secret123' }),
        status: 200,
      }),
    ],
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(titles(findings).includes('Credentials submitted over plaintext HTTP'), 'title expected');
  const f = findings.find(x => x.title === 'Credentials submitted over plaintext HTTP');
  assert.equal(f.sev, 'high');
  assert.equal(f.cwe, 'CWE-319');
  assert.equal(f.confidence, 'firm');
  // Evidence is the key name only, never the value
  assert.ok(!f.evidence.includes('secret123'), 'credential value must not appear in evidence');
});

// ---- log checks: session cookie without HttpOnly ----------------------------

test('session cookie without HttpOnly on /login response emits medium finding', () => {
  const ctx = makeCtx({
    entries: [
      entry({
        url: 'https://api.example.test/login',
        method: 'POST',
        status: 200,
        resHeaders: { 'Set-Cookie': 'sessionId=abc123; Path=/; Secure' },
      }),
    ],
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(titles(findings).includes('Session cookie set without HttpOnly on auth response'), 'title expected');
  const f = findings.find(x => x.title === 'Session cookie set without HttpOnly on auth response');
  assert.equal(f.sev, 'medium');
  assert.equal(f.cwe, 'CWE-1004');
  assert.equal(f.confidence, 'firm');
  assert.equal(f.evidence, 'sessionId', 'evidence should be the cookie name');
});

test('session cookie WITH HttpOnly flag does NOT emit finding', () => {
  const ctx = makeCtx({
    entries: [
      entry({
        url: 'https://api.example.test/login',
        method: 'POST',
        status: 200,
        resHeaders: { 'Set-Cookie': 'sessionId=abc123; Path=/; Secure; HttpOnly' },
      }),
    ],
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(
    !titles(findings).includes('Session cookie set without HttpOnly on auth response'),
    'HttpOnly present — must not fire',
  );
});

// ---- clean-path and cross-cutting checks ------------------------------------

test('clean short-lived RS256 JWT over HTTPS produces no JWT-security findings', () => {
  const iat = 1700000000;
  const exp = iat + 3600; // 1 hour
  const jwt = makeJwt({ alg: 'RS256', typ: 'JWT' }, { sub: 'user1', iat, exp });
  const ctx = makeCtx({
    entries: [
      entry({ reqHeaders: { Authorization: `Bearer ${jwt}` } }),
    ],
    securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } },
  });
  const findings = analyzeAuthIntelligence(ctx);
  const jwtTitles = [
    'JWT with alg=none observed',
    'JWT without expiry (exp) claim',
    'JWT lifetime exceeds 1 year',
    'Bearer scheme without declared bearerFormat',
  ];
  const hits = findings.filter(f => jwtTitles.includes(f.title));
  assert.equal(hits.length, 0, 'clean short-lived RS256 JWT should not produce these findings');
});

test('no finding evidence ever contains the raw JWT token', () => {
  const jwt = makeJwt({ alg: 'none', typ: 'JWT' }, { sub: 'admin', role: 'superuser' });
  const ctx = makeCtx({
    entries: [
      entry({
        reqHeaders: { Authorization: `Bearer ${jwt}` },
        resBody: JSON.stringify({ access_token: jwt }),
      }),
    ],
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(findings.length > 0, 'should have findings for alg=none JWT');
  for (const f of findings) {
    assert.ok(
      !String(f.evidence).includes(jwt),
      `finding "${f.title}" must not expose raw JWT in evidence`,
    );
  }
});

test('empty records and empty securitySchemes returns empty array', () => {
  assert.deepEqual(analyzeAuthIntelligence({ records: [], securitySchemes: {} }), []);
  assert.deepEqual(analyzeAuthIntelligence({}), []);
});

test('all findings carry category "security" and owasp "API2:2023"', () => {
  const iat = 1000000000;
  const jwt = makeJwt({ alg: 'none', typ: 'JWT' }, { sub: 'user1' });
  const ctx = makeCtx({
    entries: [
      entry({
        url: 'http://api.example.test/login',
        method: 'POST',
        reqHeaders: { Authorization: 'Basic dXNlcjpwYXNz' },
        reqBody: JSON.stringify({ password: 'pw' }),
        status: 200,
        resHeaders: { 'Set-Cookie': 'sessionId=x; Path=/' },
        resBody: JSON.stringify({ token: jwt }),
      }),
    ],
    securitySchemes: { basicAuth: { type: 'http', scheme: 'basic' } },
  });
  const findings = analyzeAuthIntelligence(ctx);
  assert.ok(findings.length > 0, 'should have findings');
  for (const f of findings) {
    assert.equal(f.category, 'security', `"${f.title}" must have category "security"`);
    assert.equal(f.owasp, 'API2:2023', `"${f.title}" must have owasp "API2:2023"`);
  }
});
