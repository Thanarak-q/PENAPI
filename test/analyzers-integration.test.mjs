import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeSpec } from '../public/js/static-analysis.js';

function spec(overrides = {}) {
  return {
    title: 'Integration API',
    version: '',
    specVersion: '3.0.0',
    baseUrls: ['https://api.example.test'],
    securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } },
    tags: ['default'],
    stats: { endpoints: 0, paths: 0 },
    endpoints: [],
    ...overrides,
  };
}

function endpoint(overrides = {}) {
  return {
    id: `${overrides.method || 'GET'} ${overrides.path || '/health'}`,
    method: overrides.method || 'GET',
    path: overrides.path || '/health',
    operationId: overrides.operationId ?? 'op',
    summary: overrides.summary || 'summary',
    description: overrides.description || 'description',
    tags: overrides.tags || ['default'],
    deprecated: !!overrides.deprecated,
    params: { path: [], query: [], header: [], cookie: [], ...(overrides.params || {}) },
    body: overrides.body || null,
    security: overrides.security ?? [{ bearerAuth: [] }],
  };
}

test('summary exposes risk score, grade, and owasp counts', () => {
  const report = analyzeSpec(spec({ endpoints: [endpoint()] }), []);
  assert.equal(typeof report.summary.riskScore, 'number');
  assert.ok(typeof report.summary.grade === 'string' && report.summary.grade.length > 0);
  assert.equal(typeof report.summary.owasp, 'object');
});

test('summary computes auth coverage over mutating operations', () => {
  const report = analyzeSpec(
    spec({
      endpoints: [
        endpoint({ method: 'POST', path: '/a', security: [] }), // unauth write
        endpoint({ method: 'POST', path: '/b', security: [{ bearerAuth: [] }] }), // authed write
        endpoint({ method: 'GET', path: '/c', security: [{ bearerAuth: [] }] }), // read
      ],
    }),
    []
  );
  const cov = report.summary.authCoverage;
  assert.equal(cov.mutating, 2);
  assert.equal(cov.mutatingUnauth, 1);
  assert.equal(cov.pct, 50);
  assert.equal(typeof report.summary.owaspCategories, 'number');
});

test('every finding carries a confidence and (where classified) an owasp id', () => {
  const report = analyzeSpec(
    spec({ endpoints: [endpoint({ method: 'POST', path: '/admin/users', security: [] })] }),
    []
  );
  assert.ok(report.findings.length > 0);
  for (const finding of report.findings) {
    assert.ok(['firm', 'tentative'].includes(finding.confidence));
    assert.equal(typeof finding.owasp, 'string');
    assert.equal(typeof finding.cwe, 'string');
  }
  // An unauthenticated admin write should be classified into the OWASP catalog.
  assert.ok(report.findings.some((f) => f.owasp.startsWith('API')));
});

test('inventory analyzer surfaces non-production base URLs through analyzeSpec', () => {
  const report = analyzeSpec(spec({ baseUrls: ['https://staging.example.test'], endpoints: [endpoint()] }), []);
  assert.ok(report.findings.some((f) => f.category === 'inventory'));
  assert.ok(report.summary.categories.inventory >= 1);
});

test('resource analyzer surfaces bulk/expensive operations through analyzeSpec', () => {
  const report = analyzeSpec(
    spec({ endpoints: [endpoint({ method: 'POST', path: '/users/bulk', operationId: 'bulkCreate' })] }),
    []
  );
  assert.ok(report.findings.some((f) => f.category === 'resource'));
});

test('response-hygiene analyzer fires from saved request logs', () => {
  const history = [
    {
      request: { method: 'GET', url: 'https://api.example.test/me', headers: {} },
      response: {
        status: 200,
        headers: {
          'access-control-allow-origin': '*',
          'set-cookie': 'session=abc; Path=/',
          'content-type': 'application/json',
        },
        body: '{"ok":true}',
      },
    },
  ];
  const report = analyzeSpec(spec({ endpoints: [endpoint({ path: '/me' })] }), history);
  assert.ok(report.findings.some((f) => f.category === 'config' && /CORS/i.test(f.title)));
  assert.ok(report.findings.some((f) => f.category === 'config' && /HttpOnly/i.test(f.title)));
});

test('pii analyzer flags secrets observed in response logs (masked)', () => {
  const history = [
    {
      request: { method: 'GET', url: 'https://api.example.test/profile', headers: {} },
      response: { status: 200, headers: { 'content-type': 'application/json' }, body: '{"email":"victim@example.test"}' },
    },
  ];
  const report = analyzeSpec(spec({ endpoints: [endpoint({ path: '/profile' })] }), history);
  const pii = report.findings.filter((f) => f.category === 'data' && f.source === 'history');
  assert.ok(pii.length >= 1);
  // The full email local-part must never appear in evidence.
  assert.ok(report.findings.every((f) => !f.evidence.includes('victim@example.test')));
});

test('auth-intelligence flags HTTP Basic scheme as a spec finding (API2)', () => {
  const report = analyzeSpec(
    spec({ securitySchemes: { basicAuth: { type: 'http', scheme: 'basic' } }, endpoints: [endpoint({ security: [{ basicAuth: [] }] })] }),
    []
  );
  const f = report.findings.find((x) => x.title === 'HTTP Basic authentication scheme in use');
  assert.ok(f, 'expected Basic scheme finding');
  assert.equal(f.owasp, 'API2:2023');
  assert.equal(f.source, 'spec');
});

test('auth-intelligence decodes a logged alg=none JWT as a high log finding', () => {
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const jwt = `${b64u({ alg: 'none', typ: 'JWT' })}.${b64u({ sub: 'admin' })}.`;
  const history = [
    {
      request: { method: 'GET', url: 'https://api.example.test/me', headers: { authorization: `Bearer ${jwt}` } },
      response: { status: 200, headers: {}, body: '{}' },
    },
  ];
  const report = analyzeSpec(spec({ endpoints: [endpoint({ path: '/me' })] }), history);
  const f = report.findings.find((x) => x.title === 'JWT with alg=none observed');
  assert.ok(f, 'expected alg=none finding');
  assert.equal(f.sev, 'high');
  assert.equal(f.source, 'history');
});

test('business-flows flags a checkout endpoint (API6)', () => {
  const report = analyzeSpec(
    spec({ endpoints: [endpoint({ method: 'POST', path: '/checkout', operationId: 'checkout' })] }),
    []
  );
  assert.ok(report.findings.some((f) => f.owasp === 'API6:2023'));
});

test('runtime-intel flags an open redirect observed in the request log (API7)', () => {
  const history = [
    {
      request: { method: 'GET', url: 'https://api.example.test/go?next=https://evil.test/x', headers: {} },
      response: { status: 302, headers: { location: 'https://evil.test/x' }, body: '' },
    },
  ];
  const report = analyzeSpec(spec({ endpoints: [endpoint({ path: '/go' })] }), history);
  const f = report.findings.find((x) => x.title === 'Open redirect: request parameter reflected in Location');
  assert.ok(f, 'expected open-redirect finding');
  assert.equal(f.owasp, 'API7:2023');
  assert.equal(f.source, 'history');
});

test('csrf-risk flags a cookie-authed state-changing request without a token', () => {
  const history = [
    {
      request: { method: 'POST', url: 'https://api.example.test/transfer', headers: { cookie: 'sid=abc', 'content-type': 'application/json' }, body: '{"amt":1}' },
      response: { status: 200, headers: {}, body: '{}' },
    },
  ];
  const report = analyzeSpec(spec({ endpoints: [endpoint({ method: 'POST', path: '/transfer' })] }), history);
  const f = report.findings.find((x) => x.cwe === 'CWE-352');
  assert.ok(f, 'expected a CSRF finding');
  assert.equal(f.source, 'history');
  assert.ok(report.findings.every((x) => !x.evidence.includes('sid=abc')));
});

test('a clean spec with no logs still produces a well-formed summary', () => {
  const report = analyzeSpec(spec({ endpoints: [endpoint()] }), []);
  assert.equal(typeof report.summary.total, 'number');
  assert.ok(report.summary.categories.config >= 0);
  assert.ok(report.summary.categories.resource >= 0);
  assert.ok(report.summary.categories.inventory >= 0);
});
