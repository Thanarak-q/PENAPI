import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeResourceConsumption } from '../public/js/analyzers/resource-consumption.js';

// ---- factory ----------------------------------------------------------------

function endpoint(overrides = {}) {
  return {
    id: `${overrides.method || 'GET'} ${overrides.path || '/health'}`,
    method: overrides.method || 'GET',
    path: overrides.path || '/health',
    operationId: overrides.operationId ?? null,
    summary: overrides.summary || '',
    description: overrides.description || '',
    tags: overrides.tags || [],
    deprecated: !!overrides.deprecated,
    params: {
      path: [],
      query: [],
      header: [],
      cookie: [],
      ...(overrides.params || {}),
    },
    body: overrides.body || null,
    security: overrides.security ?? [],
  };
}

function ctx(endpoints) {
  return { endpoints };
}

function titles(findings) {
  return findings.map((f) => f.title);
}

// ---- check 1: bulk/batch operation -----------------------------------------

test('bulk POST emits medium bulk/batch finding', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({ method: 'POST', path: '/api/users/bulk-create', operationId: 'bulkCreateUsers' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Bulk/batch operation may amplify resource use'),
    'expected bulk finding'
  );
  const found = findings.find((f) => f.title === 'Bulk/batch operation may amplify resource use');
  assert.equal(found.sev, 'medium');
  assert.equal(found.owasp, 'API4:2023');
  assert.equal(found.cwe, 'CWE-770');
  assert.equal(found.confidence, 'tentative');
});

test('bulk GET does not emit bulk finding (non-mutating)', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({ method: 'GET', path: '/api/users/batch' }),
  ]));
  assert.ok(
    !findings.some((f) => f.title === 'Bulk/batch operation may amplify resource use'),
    'GET bulk should not emit finding'
  );
});

test('operationId containing "import" on PUT emits bulk finding', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({ method: 'PUT', path: '/data', operationId: 'importRecords' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Bulk/batch operation may amplify resource use'),
    'expected bulk finding via operationId'
  );
});

// ---- check 2: expensive operation ------------------------------------------

test('export GET emits medium expensive-operation finding', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({ method: 'GET', path: '/reports/export' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Potentially expensive operation without visible limits'),
    'expected expensive finding'
  );
  const found = findings.find((f) => f.title === 'Potentially expensive operation without visible limits');
  assert.equal(found.sev, 'medium');
  assert.equal(found.cwe, 'CWE-400');
});

test('pdf generation endpoint emits expensive finding', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({ method: 'POST', path: '/invoices/render-pdf', operationId: 'renderInvoicePdf' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Potentially expensive operation without visible limits'),
    'expected expensive finding for pdf path'
  );
});

// ---- check 3: free-text / regex search param --------------------------------

test('query param named "q" emits low ReDoS/search finding', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({
      method: 'GET',
      path: '/search',
      params: { query: [{ name: 'q', in: 'query', required: false, description: '' }] },
    }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Free-text search/filter parameter — verify query cost & ReDoS limits'),
    'expected search param finding for "q"'
  );
  const found = findings.find((f) => f.title === 'Free-text search/filter parameter — verify query cost & ReDoS limits');
  assert.equal(found.sev, 'low');
  assert.equal(found.cwe, 'CWE-1333');
  assert.equal(found.evidence, 'q');
});

test('query param named "keyword" emits search finding', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({
      method: 'GET',
      path: '/items',
      params: { query: [{ name: 'keyword', in: 'query', required: false, description: '' }] },
    }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Free-text search/filter parameter — verify query cost & ReDoS limits'),
    'expected search param finding for "keyword"'
  );
});

test('only one search finding is emitted per endpoint even with multiple matching params', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({
      method: 'GET',
      path: '/search',
      params: {
        query: [
          { name: 'query', in: 'query', required: false, description: '' },
          { name: 'filter', in: 'query', required: false, description: '' },
        ],
      },
    }),
  ]));
  const searchFindings = findings.filter(
    (f) => f.title === 'Free-text search/filter parameter — verify query cost & ReDoS limits'
  );
  assert.equal(searchFindings.length, 1, 'exactly one search finding per endpoint');
});

// ---- check 4: array request body -------------------------------------------

test('top-level array body POST emits firm low array finding', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({
      method: 'POST',
      path: '/items',
      body: { contentType: 'application/json', required: true, example: [{ id: 1 }, { id: 2 }] },
    }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Array input accepted — verify maxItems / element-count cap'),
    'expected array body finding'
  );
  const found = findings.find((f) => f.title === 'Array input accepted — verify maxItems / element-count cap');
  assert.equal(found.sev, 'low');
  assert.equal(found.confidence, 'firm');
  assert.equal(found.evidence, 'request body root');
});

test('nested array field in body POST emits firm array finding with field name as evidence', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({
      method: 'PATCH',
      path: '/orders/{id}',
      body: {
        contentType: 'application/json',
        required: true,
        example: { status: 'pending', items: [{ sku: 'A', qty: 2 }] },
      },
    }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Array input accepted — verify maxItems / element-count cap'),
    'expected nested array body finding'
  );
  const found = findings.find((f) => f.title === 'Array input accepted — verify maxItems / element-count cap');
  assert.equal(found.evidence, 'items');
  assert.equal(found.confidence, 'firm');
});

test('array body on GET does not emit array finding (non-mutating)', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({
      method: 'GET',
      path: '/items',
      body: { contentType: 'application/json', required: false, example: [{ id: 1 }] },
    }),
  ]));
  assert.ok(
    !findings.some((f) => f.title === 'Array input accepted — verify maxItems / element-count cap'),
    'GET with array body should not emit finding'
  );
});

// ---- check 5: unbounded size/limit parameter --------------------------------

test('limit query param emits info size finding', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({
      method: 'GET',
      path: '/users',
      params: { query: [{ name: 'limit', in: 'query', required: false, description: '' }] },
    }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Client-controlled result-size parameter — confirm a server maximum'),
    'expected size param finding'
  );
  const found = findings.find((f) => f.title === 'Client-controlled result-size parameter — confirm a server maximum');
  assert.equal(found.sev, 'info');
  assert.equal(found.owasp, 'API4:2023');
  assert.equal(found.evidence, 'limit');
});

test('per_page query param emits info size finding', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({
      method: 'GET',
      path: '/posts',
      params: { query: [{ name: 'per_page', in: 'query', required: false, description: '' }] },
    }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'Client-controlled result-size parameter — confirm a server maximum'),
    'expected size param finding for per_page'
  );
});

// ---- check 6: GraphQL DoS angle --------------------------------------------

test('GraphQL path emits low depth/complexity finding', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({ method: 'POST', path: '/graphql' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'GraphQL endpoint — enforce query depth/complexity & disable batching if unused'),
    'expected graphql resource finding'
  );
  const found = findings.find(
    (f) => f.title === 'GraphQL endpoint — enforce query depth/complexity & disable batching if unused'
  );
  assert.equal(found.sev, 'low');
  assert.equal(found.cwe, 'CWE-770');
});

test('graphiql path emits GraphQL resource finding', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({ method: 'GET', path: '/graphiql' }),
  ]));
  assert.ok(
    findings.some((f) => f.title === 'GraphQL endpoint — enforce query depth/complexity & disable batching if unused'),
    'expected graphiql finding'
  );
});

// ---- check 7: webhook / outbound work --------------------------------------

test('webhook POST emits low outbound-work finding', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({ method: 'POST', path: '/webhooks' }),
  ]));
  assert.ok(
    findings.some((f) =>
      f.title === 'Endpoint registers outbound work (webhook/callback) — rate-limit & validate targets'
    ),
    'expected webhook finding'
  );
  const found = findings.find(
    (f) => f.title === 'Endpoint registers outbound work (webhook/callback) — rate-limit & validate targets'
  );
  assert.equal(found.sev, 'low');
  assert.equal(found.cwe, 'CWE-770');
});

test('subscribe endpoint PATCH emits outbound-work finding', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({ method: 'PATCH', path: '/notifications/subscribe', operationId: 'subscribeToNotifications' }),
  ]));
  assert.ok(
    findings.some((f) =>
      f.title === 'Endpoint registers outbound work (webhook/callback) — rate-limit & validate targets'
    ),
    'expected subscribe finding'
  );
});

test('webhook GET does not emit outbound-work finding (non-mutating)', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({ method: 'GET', path: '/webhooks' }),
  ]));
  assert.ok(
    !findings.some((f) =>
      f.title === 'Endpoint registers outbound work (webhook/callback) — rate-limit & validate targets'
    ),
    'GET /webhooks should not emit outbound-work finding'
  );
});

// ---- boring endpoint: no findings ------------------------------------------

test('plain GET /health emits no resource findings', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({ method: 'GET', path: '/health' }),
  ]));
  assert.equal(findings.length, 0, 'expected no findings for /health');
});

// ---- edge cases -------------------------------------------------------------

test('returns empty array when ctx has no endpoints', () => {
  assert.deepEqual(analyzeResourceConsumption({}), []);
  assert.deepEqual(analyzeResourceConsumption({ endpoints: [] }), []);
  assert.deepEqual(analyzeResourceConsumption(null), []);
});

test('each finding carries category resource and API4:2023 owasp tag', () => {
  const findings = analyzeResourceConsumption(ctx([
    endpoint({ method: 'POST', path: '/bulk' }),
    endpoint({ method: 'GET', path: '/export' }),
    endpoint({ method: 'POST', path: '/graphql' }),
  ]));
  assert.ok(findings.length > 0, 'expected at least one finding');
  for (const f of findings) {
    assert.equal(f.category, 'resource', `finding "${f.title}" should have category 'resource'`);
    assert.equal(f.owasp, 'API4:2023', `finding "${f.title}" should reference API4:2023`);
  }
});
