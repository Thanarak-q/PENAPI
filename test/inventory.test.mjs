import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeInventory } from '../public/js/analyzers/inventory.js';

// ---- factories ----------------------------------------------------------------

function endpoint(overrides = {}) {
  const method = overrides.method || 'GET';
  const path = overrides.path || '/health';
  return {
    id: `${method} ${path}`,
    method,
    path,
    operationId: overrides.operationId || null,
    summary: overrides.summary || '',
    description: overrides.description || '',
    tags: overrides.tags || [],
    deprecated: !!overrides.deprecated,
    params: { path: [], query: [], header: [], cookie: [], ...(overrides.params || {}) },
    body: overrides.body || null,
    security: overrides.security || [],
  };
}

function makeCtx(overrides = {}) {
  return {
    spec: {
      title: 'Test API',
      version: '1.0.0',
      specVersion: '3.0.0',
      baseUrls: ['https://api.example.com'],
      securitySchemes: {},
      tags: [],
      stats: {},
      ...(overrides.spec || {}),
    },
    endpoints: overrides.endpoints || [],
    securitySchemes: overrides.securitySchemes || {},
    history: overrides.history || [],
    records: overrides.records || [],
  };
}

// ---- empty / guard ----------------------------------------------------------------

test('returns empty array when ctx is empty', () => {
  const findings = analyzeInventory({});
  assert.deepEqual(findings, []);
});

test('returns empty array when endpoints and baseUrls are empty', () => {
  const findings = analyzeInventory(makeCtx({ spec: { baseUrls: [], version: '1.0.0' } }));
  assert.deepEqual(findings, []);
});

// ---- check 1a: multiple versions — info summary --------------------------------

test('emits info finding when two numeric API versions are present', () => {
  const findings = analyzeInventory(makeCtx({
    endpoints: [
      endpoint({ path: '/v1/users' }),
      endpoint({ path: '/v2/users' }),
    ],
  }));
  assert.ok(
    findings.some((f) => f.title === 'API exposes multiple versions' && f.sev === 'info'),
    'missing multiple-versions info finding',
  );
});

test('multiple-versions evidence lists versions in ascending order', () => {
  const findings = analyzeInventory(makeCtx({
    endpoints: [
      endpoint({ path: '/v2/items' }),
      endpoint({ path: '/v1/items' }),
    ],
  }));
  const f = findings.find((f) => f.title === 'API exposes multiple versions');
  assert.ok(f, 'finding must exist');
  assert.match(f.evidence, /v1.*v2/i, 'evidence should list v1 before v2');
});

test('does not emit multiple-versions when only one numeric version present', () => {
  const findings = analyzeInventory(makeCtx({
    endpoints: [endpoint({ path: '/v1/users' })],
  }));
  assert.ok(
    !findings.some((f) => f.title === 'API exposes multiple versions'),
    'should not flag a single numeric version',
  );
});

// ---- check 1b: old version still exposed ----------------------------------------

test('emits medium finding for old numeric version when a newer one exists', () => {
  const findings = analyzeInventory(makeCtx({
    endpoints: [
      endpoint({ path: '/v1/users' }),
      endpoint({ path: '/v2/users' }),
    ],
  }));
  assert.ok(
    findings.some(
      (f) =>
        f.title === 'Older API version still exposed (potential shadow/unmaintained)' &&
        f.sev === 'medium',
    ),
    'missing old-version medium finding',
  );
});

test('old-version finding evidence includes the version token and operation count', () => {
  const findings = analyzeInventory(makeCtx({
    endpoints: [
      endpoint({ path: '/v1/users' }),
      endpoint({ path: '/v1/items' }),
      endpoint({ path: '/v2/users' }),
    ],
  }));
  const f = findings.find(
    (f) => f.title === 'Older API version still exposed (potential shadow/unmaintained)',
  );
  assert.ok(f, 'finding must exist');
  assert.match(f.evidence, /v1/i, 'evidence should mention the old version');
  assert.match(f.evidence, /2 operations/, 'evidence should count the 2 v1 operations');
});

// ---- check 2: pre-release surface -----------------------------------------------

test('emits low finding for beta path segment', () => {
  const findings = analyzeInventory(makeCtx({
    endpoints: [endpoint({ path: '/api/beta/feature' })],
  }));
  assert.ok(
    findings.some((f) => f.title === 'Pre-release API surface exposed' && f.sev === 'low'),
    'missing beta low finding',
  );
});

test('emits low finding for alpha path segment', () => {
  const findings = analyzeInventory(makeCtx({
    endpoints: [endpoint({ path: '/alpha/payments' })],
  }));
  assert.ok(
    findings.some((f) => f.title === 'Pre-release API surface exposed' && f.sev === 'low'),
    'missing alpha low finding',
  );
});

// ---- check 3: internal route in spec --------------------------------------------

test('emits medium finding for /internal/ path', () => {
  const findings = analyzeInventory(makeCtx({
    endpoints: [endpoint({ path: '/internal/health' })],
  }));
  assert.ok(
    findings.some(
      (f) =>
        f.title === 'Internal/private route present in published spec' && f.sev === 'medium',
    ),
    'missing internal-route medium finding',
  );
});

test('emits medium finding for /private/ path', () => {
  const findings = analyzeInventory(makeCtx({
    endpoints: [endpoint({ path: '/api/private/data' })],
  }));
  assert.ok(
    findings.some((f) => f.title === 'Internal/private route present in published spec'),
    'missing private-route finding',
  );
});

// ---- check 4: non-production base URL -------------------------------------------

test('emits medium tentative finding for staging base URL', () => {
  const findings = analyzeInventory(makeCtx({
    spec: { baseUrls: ['https://staging.example.com'], version: '1.0.0' },
  }));
  assert.ok(
    findings.some(
      (f) =>
        f.title === 'Non-production server URL in spec' &&
        f.sev === 'medium' &&
        f.confidence === 'tentative',
    ),
    'missing staging non-prod finding with tentative confidence',
  );
});

test('emits finding for localhost base URL', () => {
  const findings = analyzeInventory(makeCtx({
    spec: { baseUrls: ['http://localhost:3000'], version: '1.0.0' },
  }));
  assert.ok(
    findings.some((f) => f.title === 'Non-production server URL in spec'),
    'missing localhost finding',
  );
});

// ---- check 5: plaintext HTTP base URL -------------------------------------------

test('emits medium finding for http:// base URL', () => {
  const findings = analyzeInventory(makeCtx({
    spec: { baseUrls: ['http://api.example.com'], version: '1.0.0' },
  }));
  assert.ok(
    findings.some((f) => f.title === 'Base URL uses plaintext HTTP' && f.sev === 'medium'),
    'missing plaintext HTTP finding',
  );
});

test('plaintext HTTP finding carries CWE-319', () => {
  const findings = analyzeInventory(makeCtx({
    spec: { baseUrls: ['http://api.example.com'], version: '1.0.0' },
  }));
  const f = findings.find((f) => f.title === 'Base URL uses plaintext HTTP');
  assert.ok(f, 'finding must exist');
  assert.equal(f.cwe, 'CWE-319');
});

// ---- check 6: mixed schemes -----------------------------------------------------

test('emits low finding when both http and https base URLs are declared', () => {
  const findings = analyzeInventory(makeCtx({
    spec: {
      baseUrls: ['http://api.example.com', 'https://api.example.com'],
      version: '1.0.0',
    },
  }));
  assert.ok(
    findings.some((f) => f.title === 'Mixed HTTP and HTTPS base URLs' && f.sev === 'low'),
    'missing mixed-schemes finding',
  );
});

test('does not emit mixed-schemes when only https is used', () => {
  const findings = analyzeInventory(makeCtx({
    spec: { baseUrls: ['https://api.example.com', 'https://api2.example.com'], version: '1.0.0' },
  }));
  assert.ok(
    !findings.some((f) => f.title === 'Mixed HTTP and HTTPS base URLs'),
    'should not flag when only https is used',
  );
});

// ---- check 7: multiple servers --------------------------------------------------

test('emits info finding when 3 or more server URLs are declared', () => {
  const findings = analyzeInventory(makeCtx({
    spec: {
      baseUrls: [
        'https://api.example.com',
        'https://api-eu.example.com',
        'https://api-us.example.com',
      ],
      version: '1.0.0',
    },
  }));
  assert.ok(
    findings.some((f) => f.title === 'Multiple server URLs declared' && f.sev === 'info'),
    'missing multiple-servers info finding',
  );
});

test('does not emit multiple-servers when fewer than 3 URLs', () => {
  const findings = analyzeInventory(makeCtx({
    spec: {
      baseUrls: ['https://api.example.com', 'https://api-eu.example.com'],
      version: '1.0.0',
    },
  }));
  assert.ok(
    !findings.some((f) => f.title === 'Multiple server URLs declared'),
    'should not flag fewer than 3 servers',
  );
});

// ---- check 8: no version indicator ----------------------------------------------

test('emits info finding when no version in paths and no spec version', () => {
  const findings = analyzeInventory(makeCtx({
    spec: { baseUrls: ['https://api.example.com'], version: '' },
    endpoints: [endpoint({ path: '/users' }), endpoint({ path: '/items' })],
  }));
  assert.ok(
    findings.some((f) => f.title === 'No API version indicator found' && f.sev === 'info'),
    'missing no-version info finding',
  );
});

test('does not emit no-version finding when spec.version is populated', () => {
  const findings = analyzeInventory(makeCtx({
    spec: { baseUrls: ['https://api.example.com'], version: '2.0.0' },
    endpoints: [endpoint({ path: '/users' })],
  }));
  assert.ok(
    !findings.some((f) => f.title === 'No API version indicator found'),
    'should not flag when spec version is declared',
  );
});

test('does not emit no-version finding when a version segment exists in a path', () => {
  const findings = analyzeInventory(makeCtx({
    spec: { baseUrls: ['https://api.example.com'], version: '' },
    endpoints: [endpoint({ path: '/v1/users' })],
  }));
  assert.ok(
    !findings.some((f) => f.title === 'No API version indicator found'),
    'should not flag when path contains a version segment',
  );
});

// ---- category / owasp contract --------------------------------------------------

test('all findings carry category inventory and owasp API9:2023', () => {
  const findings = analyzeInventory(makeCtx({
    spec: {
      baseUrls: ['http://staging.example.com', 'https://api.example.com', 'https://api2.example.com'],
      version: '',
    },
    endpoints: [
      endpoint({ path: '/v1/users' }),
      endpoint({ path: '/v2/users' }),
      endpoint({ path: '/internal/debug' }),
      endpoint({ path: '/beta/feature' }),
    ],
  }));
  assert.ok(findings.length > 0, 'should produce at least one finding');
  for (const f of findings) {
    assert.equal(f.category, 'inventory', `finding "${f.title}" has wrong category`);
    assert.equal(f.owasp, 'API9:2023', `finding "${f.title}" has wrong owasp`);
  }
});
