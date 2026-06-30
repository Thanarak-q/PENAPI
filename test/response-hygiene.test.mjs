import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeResponseHygiene } from '../public/js/analyzers/response-hygiene.js';
import { eachHistory } from '../public/js/analyzers/shared.js';

// ---- test helpers -----------------------------------------------------------

function makeCtx(historyEntries, endpoints = []) {
  const history = historyEntries;
  const records = eachHistory(history, endpoints);
  return { spec: {}, endpoints, securitySchemes: {}, history, records };
}

function makeEntry(opts = {}) {
  return {
    request: {
      method: opts.method || 'GET',
      url: opts.url || 'https://api.example.test/test',
      headers: opts.reqHeaders || {},
    },
    response: {
      status: opts.status ?? 200,
      headers: opts.resHeaders || {},
      body: opts.body || '',
    },
  };
}

// ---- tests ------------------------------------------------------------------

test('empty history returns empty array', () => {
  const result = analyzeResponseHygiene(makeCtx([]));
  assert.deepEqual(result, []);
});

test('zero-status record is skipped gracefully', () => {
  const entry = makeEntry({ status: 0 });
  const result = analyzeResponseHygiene(makeCtx([entry]));
  assert.equal(result.length, 0);
});

// --- CORS ---

test('wildcard ACAO flagged as medium CORS allows any origin', () => {
  const entry = makeEntry({ resHeaders: { 'access-control-allow-origin': '*' } });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'CORS allows any origin' &&
    f.sev === 'medium' &&
    f.category === 'config' &&
    f.owasp === 'API8:2023'
  ));
});

test('wildcard ACAO with ACAC true escalated to high credentials finding', () => {
  const entry = makeEntry({
    resHeaders: {
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'CORS allows credentials with permissive origin' &&
    f.sev === 'high' &&
    f.owasp === 'API8:2023'
  ));
  // wildcard-only finding should not appear
  assert.ok(!findings.some((f) => f.title === 'CORS allows any origin'));
});

test('reflected cross-origin ACAO without credentials is high', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/users',
    reqHeaders: { origin: 'https://evil.example.com' },
    resHeaders: { 'access-control-allow-origin': 'https://evil.example.com' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'CORS reflects arbitrary origin' && f.sev === 'high'
  ));
});

test('reflected cross-origin ACAO with ACAC true is high credentials finding', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/users',
    reqHeaders: { origin: 'https://evil.example.com' },
    resHeaders: {
      'access-control-allow-origin': 'https://evil.example.com',
      'access-control-allow-credentials': 'true',
    },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'CORS allows credentials with permissive origin' &&
    f.sev === 'high' &&
    f.owasp === 'API8:2023'
  ));
});

test('same-origin reflected ACAO is not flagged', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/users',
    reqHeaders: { origin: 'https://api.example.test' },
    resHeaders: { 'access-control-allow-origin': 'https://api.example.test' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(!findings.some((f) => f.title === 'CORS reflects arbitrary origin'));
});

// --- Security headers ---

test('missing X-Content-Type-Options is low', () => {
  const entry = makeEntry({ status: 200, resHeaders: { 'content-type': 'application/json' } });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'Missing X-Content-Type-Options header' &&
    f.sev === 'low' &&
    f.owasp === 'API8:2023'
  ));
});

test('HSTS missing over HTTPS flagged as medium', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/secure',
    status: 200,
    resHeaders: { 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'HSTS not set over HTTPS' && f.sev === 'medium'
  ));
});

test('HSTS not flagged over plain HTTP', () => {
  const entry = makeEntry({
    url: 'http://api.example.test/plain',
    status: 200,
    resHeaders: {},
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(!findings.some((f) => f.title === 'HSTS not set over HTTPS'));
});

test('clickjacking protection missing when neither X-Frame-Options nor frame-ancestors in CSP', () => {
  const entry = makeEntry({
    status: 200,
    resHeaders: { 'content-security-policy': 'default-src \'self\'' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) => f.title === 'Clickjacking protection missing' && f.sev === 'low'));
});

test('frame-ancestors in CSP suppresses clickjacking finding', () => {
  const entry = makeEntry({
    status: 200,
    resHeaders: { 'content-security-policy': 'default-src \'self\'; frame-ancestors \'none\'' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(!findings.some((f) => f.title === 'Clickjacking protection missing'));
});

test('security headers not checked on 4xx responses', () => {
  const entry = makeEntry({ status: 404, resHeaders: {} });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(!findings.some((f) => f.title === 'Missing X-Content-Type-Options header'));
});

test('same missing header deduped to one finding across multiple records', () => {
  const e1 = makeEntry({ url: 'https://api.example.test/a', status: 200, resHeaders: {} });
  const e2 = makeEntry({ url: 'https://api.example.test/b', status: 200, resHeaders: {} });
  const findings = analyzeResponseHygiene(makeCtx([e1, e2]));
  const xcto = findings.filter((f) => f.title === 'Missing X-Content-Type-Options header');
  assert.equal(xcto.length, 1);
});

// --- Cookies ---

test('cookie missing HttpOnly flagged as medium', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/login',
    resHeaders: { 'set-cookie': 'session=abc123; Path=/' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'Cookie missing HttpOnly' &&
    f.sev === 'medium' &&
    f.category === 'config' &&
    f.evidence === 'session'
  ));
});

test('cookie missing Secure flag on HTTPS flagged as medium', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/login',
    resHeaders: { 'set-cookie': 'session=abc123; HttpOnly; Path=/' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'Cookie missing Secure flag' && f.sev === 'medium'
  ));
});

test('cookie missing Secure flag on HTTP is not flagged', () => {
  const entry = makeEntry({
    url: 'http://api.example.test/login',
    resHeaders: { 'set-cookie': 'session=abc123; HttpOnly; Path=/' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(!findings.some((f) => f.title === 'Cookie missing Secure flag'));
});

test('cookie missing SameSite flagged as low', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/login',
    resHeaders: { 'set-cookie': 'session=abc123; HttpOnly; Secure; Path=/' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) => f.title === 'Cookie missing SameSite' && f.sev === 'low'));
});

test('multiple cookies via newline separator each checked independently', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/login',
    resHeaders: { 'set-cookie': 'session=abc; HttpOnly; Secure; SameSite=Strict\ncsrf=xyz; Path=/' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  // csrf cookie is missing HttpOnly
  assert.ok(findings.some((f) => f.title === 'Cookie missing HttpOnly' && f.evidence === 'csrf'));
  // session cookie should not trigger HttpOnly or Secure
  assert.ok(!findings.some((f) => f.title === 'Cookie missing HttpOnly' && f.evidence === 'session'));
});

// --- Fingerprint disclosure ---

test('Server header triggers fingerprint finding', () => {
  const entry = makeEntry({ resHeaders: { 'server': 'nginx/1.18.0' } });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'Technology fingerprint disclosed in response header' && f.sev === 'low'
  ));
});

test('X-Powered-By header triggers fingerprint finding', () => {
  const entry = makeEntry({ resHeaders: { 'x-powered-by': 'PHP/7.4.0' } });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'Technology fingerprint disclosed in response header'
  ));
});

// --- Stack trace / verbose errors ---

test('Python traceback in 500 body flagged as medium', () => {
  const entry = makeEntry({
    status: 500,
    body: 'Error\nTraceback (most recent call last):\n  File "app.py", line 42',
    resHeaders: {},
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'Verbose error / stack trace in response body' &&
    f.sev === 'medium' &&
    f.owasp === 'API8:2023'
  ));
});

test('JS stack frame in 400 body flagged as medium', () => {
  const entry = makeEntry({
    status: 400,
    body: 'Error: bad input\n    at processRequest (server.js:123:45)',
    resHeaders: {},
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'Verbose error / stack trace in response body' && f.sev === 'medium'
  ));
});

test('stack trace not flagged on 2xx response', () => {
  const entry = makeEntry({
    status: 200,
    body: 'Traceback (most recent call last):\n  File "app.py", line 1',
    resHeaders: {},
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(!findings.some((f) => f.title === 'Verbose error / stack trace in response body'));
});

// --- Content-type mismatch ---

test('JSON body with text/plain content-type flagged as low', () => {
  const entry = makeEntry({
    status: 200,
    body: '{"error":"not found"}',
    resHeaders: { 'content-type': 'text/plain' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'JSON body served with non-JSON Content-Type' && f.sev === 'low'
  ));
});

test('JSON body with correct content-type not flagged for mismatch', () => {
  const entry = makeEntry({
    status: 200,
    body: '{"id":1}',
    resHeaders: { 'content-type': 'application/json' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(!findings.some((f) => f.title === 'JSON body served with non-JSON Content-Type'));
});

test('API path with HTML 200 response flagged as info', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/api/v1/users',
    status: 200,
    body: '<html></html>',
    resHeaders: { 'content-type': 'text/html; charset=utf-8' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'API endpoint returned HTML' && f.sev === 'info'
  ));
});

// --- Rate limiting on auth endpoints ---

test('no rate-limit headers on /login flagged as low', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/login',
    status: 200,
    resHeaders: { 'content-type': 'application/json' },
    body: '{"token":"xyz"}',
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) =>
    f.title === 'No rate-limit headers on authentication response' &&
    f.sev === 'low' &&
    f.owasp === 'API8:2023'
  ));
});

test('no rate-limit headers on /v1/auth/token flagged', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/v1/auth/token',
    status: 200,
    resHeaders: {},
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(findings.some((f) => f.title === 'No rate-limit headers on authentication response'));
});

test('x-ratelimit-limit header suppresses rate-limit finding', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/login',
    status: 200,
    resHeaders: { 'x-ratelimit-limit': '10' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(!findings.some((f) => f.title === 'No rate-limit headers on authentication response'));
});

test('retry-after header suppresses rate-limit finding', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/signin',
    status: 429,
    resHeaders: { 'retry-after': '60' },
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(!findings.some((f) => f.title === 'No rate-limit headers on authentication response'));
});

test('non-auth path not flagged for missing rate-limit headers', () => {
  const entry = makeEntry({
    url: 'https://api.example.test/users/123',
    status: 200,
    resHeaders: {},
  });
  const findings = analyzeResponseHygiene(makeCtx([entry]));
  assert.ok(!findings.some((f) => f.title === 'No rate-limit headers on authentication response'));
});
