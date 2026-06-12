import test from 'node:test';
import assert from 'node:assert/strict';

import {
  parseHeaders,
  auditHeaders,
  auditRawHeaders,
  summarize,
} from '../public/js/headers-core.js';

test('parseHeaders lower-cases names and skips status line + Set-Cookie', () => {
  const h = parseHeaders('HTTP/1.1 200 OK\nContent-Type: text/html\nSet-Cookie: a=1\nServer: nginx');
  assert.equal(h['content-type'], 'text/html');
  assert.equal(h['server'], 'nginx');
  assert.ok(!('set-cookie' in h));
});

test('auditHeaders flags all core headers missing on a bare response', () => {
  const findings = auditHeaders(parseHeaders('Content-Type: text/html'));
  const missing = findings.filter((f) => f.level === 'missing').map((f) => f.header);
  assert.ok(missing.includes('Content-Security-Policy'));
  assert.ok(missing.includes('Strict-Transport-Security'));
  assert.ok(missing.includes('X-Content-Type-Options'));
  assert.ok(missing.includes('X-Frame-Options'));
  assert.ok(missing.includes('Referrer-Policy'));
});

test('auditHeaders marks unsafe-inline CSP as weak', () => {
  const f = auditHeaders(parseHeaders("Content-Security-Policy: default-src 'self' 'unsafe-inline'"));
  const csp = f.find((x) => x.header === 'Content-Security-Policy');
  assert.equal(csp.level, 'weak');
});

test('auditHeaders treats short HSTS max-age as weak', () => {
  const f = auditHeaders(parseHeaders('Strict-Transport-Security: max-age=3600'));
  const hsts = f.find((x) => x.header === 'Strict-Transport-Security');
  assert.equal(hsts.level, 'weak');
});

test('auditHeaders accepts a long HSTS max-age', () => {
  const f = auditHeaders(parseHeaders('Strict-Transport-Security: max-age=31536000; includeSubDomains'));
  const hsts = f.find((x) => x.header === 'Strict-Transport-Security');
  assert.equal(hsts.level, 'ok');
});

test('CSP frame-ancestors covers X-Frame-Options', () => {
  const f = auditHeaders(parseHeaders("Content-Security-Policy: frame-ancestors 'none'"));
  const xfo = f.find((x) => x.header === 'X-Frame-Options');
  assert.equal(xfo.level, 'ok');
});

test('auditHeaders flags Server / X-Powered-By disclosure', () => {
  const f = auditHeaders(parseHeaders('Server: Apache/2.4.1\nX-Powered-By: PHP/8.1'));
  assert.ok(f.some((x) => x.header === 'Server' && x.level === 'weak'));
  assert.ok(f.some((x) => x.header === 'X-Powered-By' && x.level === 'weak'));
});

test('wildcard ACAO with credentials is critical (missing level)', () => {
  const f = auditHeaders(parseHeaders('Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true'));
  const cors = f.find((x) => x.header === 'Access-Control-Allow-Origin');
  assert.equal(cors.level, 'missing');
});

test('auditRawHeaders + summarize give level counts', () => {
  const findings = auditRawHeaders('Content-Type: text/html');
  const s = summarize(findings);
  assert.ok(s.missing >= 5);
  assert.equal(typeof s.ok, 'number');
});
