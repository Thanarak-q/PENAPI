import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeResponse } from '../public/js/analyze.js';

const titles = (fs) => fs.map((f) => f.title);

test('returns [] for an errored result', () => {
  assert.deepEqual(analyzeResponse({ error: 'timeout' }), []);
  assert.deepEqual(analyzeResponse(null), []);
});

test('flags all missing security headers on a bare response', () => {
  const t = titles(analyzeResponse({ status: 200, headers: { 'content-type': 'text/html' } }));
  assert.ok(t.includes('HSTS not set'));
  assert.ok(t.includes('No Content-Security-Policy'));
  assert.ok(t.includes('X-Frame-Options / frame-ancestors missing'));
  assert.ok(t.includes('Permissions-Policy not set'));
});

test('CSP frame-ancestors suppresses the X-Frame-Options finding', () => {
  const t = titles(analyzeResponse({ status: 200, headers: { 'content-security-policy': "frame-ancestors 'none'" } }));
  assert.ok(!t.includes('X-Frame-Options / frame-ancestors missing'));
});

test('flags weak HSTS max-age and unsafe CSP', () => {
  const t = titles(analyzeResponse({
    status: 200,
    headers: { 'strict-transport-security': 'max-age=3600', 'content-security-policy': "default-src 'self' 'unsafe-inline'" },
  }));
  assert.ok(t.includes('Weak HSTS max-age'));
  assert.ok(t.includes("CSP allows 'unsafe-inline'/'unsafe-eval'"));
});

test('accepts a strong HSTS max-age', () => {
  const t = titles(analyzeResponse({ status: 200, headers: { 'strict-transport-security': 'max-age=31536000' } }));
  assert.ok(!t.includes('Weak HSTS max-age'));
});

test('flags wildcard, null, and credentialed CORS', () => {
  assert.ok(titles(analyzeResponse({ status: 200, headers: { 'access-control-allow-origin': '*' } })).includes('CORS allows any origin (*)'));
  assert.ok(titles(analyzeResponse({ status: 200, headers: { 'access-control-allow-origin': 'null' } })).includes('CORS allows the "null" origin'));
  const cred = analyzeResponse({ status: 200, headers: { 'access-control-allow-origin': 'https://evil.com', 'access-control-allow-credentials': 'true' } });
  assert.ok(titles(cred).includes('CORS reflects origin with credentials'));
});

test('flags weak cookie flags including SameSite=None without Secure', () => {
  const t = titles(analyzeResponse({ status: 200, headers: { 'set-cookie': 'sid=abc; SameSite=None' } }));
  assert.ok(t.includes('Cookie without HttpOnly'));
  assert.ok(t.includes('Cookie SameSite=None without Secure'));
});

test('flags a cacheable sensitive response', () => {
  const t = titles(analyzeResponse({ status: 200, headers: { 'set-cookie': 'sid=abc' } }));
  assert.ok(t.includes('Sensitive response may be cacheable'));
});

test('flags 5xx status and verbose errors / leaked secrets in the body', () => {
  const stack = analyzeResponse({ status: 500, headers: {}, body: 'Traceback (most recent call last):\n  File "app.py"' });
  assert.ok(titles(stack).includes('Server error 500'));
  assert.ok(titles(stack).includes('Verbose error / stack trace in body'));

  const key = analyzeResponse({ status: 200, headers: {}, body: 'aws_key=AKIA' + 'IOSFODNN7EXAMPLE' });
  assert.ok(titles(key).includes('AWS access key in response body'));

  const pk = analyzeResponse({ status: 200, headers: {}, body: '-----BEGIN RSA PRIVATE KEY-----' });
  assert.ok(titles(pk).includes('Private key in response body'));
});

test('a well-hardened response yields no high/medium findings', () => {
  const findings = analyzeResponse({
    status: 200,
    headers: {
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'permissions-policy': 'geolocation=()',
    },
    body: '{"ok":true}',
  });
  assert.ok(!findings.some((f) => f.sev === 'high' || f.sev === 'medium'));
});

test('findings are tagged with OWASP API ids and CWEs', () => {
  const cors = analyzeResponse({ status: 200, headers: { 'access-control-allow-origin': '*' } });
  const f = cors.find((x) => /CORS allows any origin/.test(x.title));
  assert.equal(f.owasp, 'API8:2023');
  assert.equal(f.cwe, 'CWE-16');
});

test('a leaked AWS key in the body is tagged as API3 sensitive-data exposure', () => {
  // Split literal so the pre-commit secret scanner doesn't flag this fixture
  // (the runtime value is still the AWS docs EXAMPLE key, not a real credential).
  const out = analyzeResponse({ status: 200, headers: {}, body: 'key=AKIA' + 'IOSFODNN7EXAMPLE' });
  const f = out.find((x) => /AWS access key/.test(x.title));
  assert.equal(f.owasp, 'API3:2023');
  assert.equal(f.cwe, 'CWE-312');
});

test('every finding carries non-empty owasp/cwe fields', () => {
  const out = analyzeResponse({ status: 500, headers: { 'set-cookie': 'sid=x' }, body: 'Traceback (most recent call last)' });
  assert.ok(out.length > 0);
  for (const f of out) {
    assert.equal(typeof f.owasp, 'string');
    assert.ok(f.owasp.startsWith('API'));
    assert.match(f.cwe, /^CWE-\d+$/);
  }
});
