import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeRuntimeIntel } from '../public/js/analyzers/runtime-intel.js';
import { eachHistory } from '../public/js/analyzers/shared.js';

// ---- helpers -----------------------------------------------------------------

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

function makeCtx(entries = []) {
  return { records: eachHistory(entries, []) };
}

// ---- general -----------------------------------------------------------------

test('empty records returns empty array', () => {
  assert.deepEqual(analyzeRuntimeIntel({ records: [] }), []);
  assert.deepEqual(analyzeRuntimeIntel({}), []);
});

// ---- Check 1: reflected request input ----------------------------------------

test('query param value reflected in 200 response body emits low injection finding', () => {
  const ctx = makeCtx([
    entry({
      url: 'https://api.example.test/search?q=hello-world',
      resBody: '{"results":[],"query":"hello-world"}',
      status: 200,
    }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  assert.ok(
    findings.some(f =>
      f.title === 'Request input reflected in response body' &&
      f.sev === 'low' &&
      f.owasp === 'API8:2023',
    ),
    'should emit reflected input finding',
  );
  const f = findings.find(f => f.title === 'Request input reflected in response body');
  assert.equal(f.category, 'injection');
  assert.equal(f.cwe, 'CWE-79');
  assert.equal(f.confidence, 'tentative');
  assert.ok(f.evidence.includes('q'), 'evidence should include param name');
});

test('reflected input evidence does not contain an overly long raw dump', () => {
  const longVal = 'abcdef-repeated-value-abcdef';
  const bigBody = longVal + 'X'.repeat(500);
  const ctx = makeCtx([
    entry({
      url: `https://api.example.test/search?q=${encodeURIComponent(longVal)}`,
      resBody: bigBody,
      status: 200,
    }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  const f = findings.find(f => f.title === 'Request input reflected in response body');
  assert.ok(f, 'should have a reflection finding');
  assert.ok(f.evidence.length <= 120, `evidence too long (${f.evidence.length} chars)`);
});

test('purely numeric query param value is NOT flagged as reflected input', () => {
  const ctx = makeCtx([
    entry({
      url: 'https://api.example.test/items?page=12345',
      resBody: '{"page":12345,"items":[]}',
      status: 200,
    }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  assert.ok(
    !findings.some(f => f.title === 'Request input reflected in response body'),
    'numeric-only value must not trigger reflection finding',
  );
});

test('short (<6 char) query param value is NOT flagged as reflected input', () => {
  const ctx = makeCtx([
    entry({
      url: 'https://api.example.test/items?id=abc',
      resBody: '{"id":"abc","name":"thing"}',
      status: 200,
    }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  assert.ok(
    !findings.some(f => f.title === 'Request input reflected in response body'),
    'short value must not trigger reflection finding',
  );
});

test('request body field string value reflected in 200 response emits finding', () => {
  const ctx = makeCtx([
    entry({
      url: 'https://api.example.test/echo',
      method: 'POST',
      reqBody: JSON.stringify({ username: 'alice-test-user' }),
      resBody: '{"message":"Hello alice-test-user!"}',
      status: 200,
    }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  assert.ok(
    findings.some(f => f.title === 'Request input reflected in response body'),
    'body field reflected in response should emit finding',
  );
  const f = findings.find(f => f.title === 'Request input reflected in response body');
  assert.ok(f.evidence.includes('username'), 'evidence should include the field name');
});

// ---- Check 2: open redirect --------------------------------------------------

test('redirect param value reflected in Location header emits medium injection finding', () => {
  const ctx = makeCtx([
    entry({
      url: 'https://api.example.test/login?next=https://evil.example.com',
      status: 302,
      resHeaders: { Location: 'https://evil.example.com/dashboard' },
    }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  assert.ok(
    findings.some(f =>
      f.title === 'Open redirect: request parameter reflected in Location' &&
      f.sev === 'medium' &&
      f.owasp === 'API7:2023',
    ),
    'should emit open redirect finding',
  );
  const f = findings.find(f => f.title === 'Open redirect: request parameter reflected in Location');
  assert.equal(f.category, 'injection');
  assert.equal(f.cwe, 'CWE-601');
  assert.equal(f.confidence, 'firm');
  assert.ok(f.evidence.includes('next'), 'evidence should include the param name');
  assert.ok(f.evidence.length <= 120, 'evidence must not be an overly long dump');
});

test('3xx without a matching redirect param name does NOT emit open redirect finding', () => {
  const ctx = makeCtx([
    entry({
      url: 'https://api.example.test/old-page?ref=homepage',
      status: 301,
      resHeaders: { Location: 'https://api.example.test/new-page' },
    }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  assert.ok(
    !findings.some(f => f.title === 'Open redirect: request parameter reflected in Location'),
    'non-redirect param name must not trigger open redirect finding',
  );
});

// ---- Check 3: GraphQL introspection -----------------------------------------

test('response containing __schema on /graphql path emits medium config finding', () => {
  const ctx = makeCtx([
    entry({
      url: 'https://api.example.test/graphql',
      method: 'POST',
      reqBody: JSON.stringify({ query: '{ __schema { types { name } } }' }),
      resBody: JSON.stringify({ data: { __schema: { types: [] } } }),
      status: 200,
    }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  assert.ok(
    findings.some(f =>
      f.title === 'GraphQL introspection appears enabled' &&
      f.sev === 'medium' &&
      f.owasp === 'API8:2023',
    ),
    'should emit GraphQL introspection finding',
  );
  const f = findings.find(f => f.title === 'GraphQL introspection appears enabled');
  assert.equal(f.category, 'config');
  assert.equal(f.cwe, 'CWE-200');
  assert.equal(f.confidence, 'firm');
  assert.equal(f.evidence, 'response exposes __schema/__type');
});

test('normal 200 JSON without __schema or internal fields does NOT emit graphql or diag finding', () => {
  const ctx = makeCtx([
    entry({
      url: 'https://api.example.test/users',
      resBody: JSON.stringify({ users: [{ id: 1, name: 'Alice' }] }),
      status: 200,
    }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  assert.ok(
    !findings.some(f => f.title === 'GraphQL introspection appears enabled'),
    'normal 200 must not trigger graphql finding',
  );
  assert.ok(
    !findings.some(f => f.title === 'Error response exposes internal diagnostic fields'),
    'normal 200 must not trigger diagnostic finding',
  );
});

// ---- Check 4: numeric object identifiers ------------------------------------

test('GET /users/5 emits low idor finding with path template in evidence', () => {
  const ctx = makeCtx([
    entry({
      url: 'https://api.example.test/users/5',
      method: 'GET',
      status: 200,
      resBody: JSON.stringify({ id: 5, name: 'Alice' }),
    }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  assert.ok(
    findings.some(f =>
      f.title === 'Sequential/numeric object identifier observed' &&
      f.sev === 'low' &&
      f.owasp === 'API1:2023',
    ),
    'should emit numeric id finding',
  );
  const f = findings.find(f => f.title === 'Sequential/numeric object identifier observed');
  assert.equal(f.category, 'idor');
  assert.equal(f.cwe, 'CWE-639');
  assert.equal(f.confidence, 'tentative');
  assert.ok(f.evidence.includes('{id}'), 'evidence should use the {id} path template');
  assert.ok(f.evidence.includes('5'), 'evidence should include the observed id value');
});

test('same path template across multiple records is deduped to one finding', () => {
  const ctx = makeCtx([
    entry({ url: 'https://api.example.test/users/1', method: 'GET', status: 200, resBody: '{}' }),
    entry({ url: 'https://api.example.test/users/2', method: 'GET', status: 200, resBody: '{}' }),
    entry({ url: 'https://api.example.test/users/3', method: 'GET', status: 200, resBody: '{}' }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  const idFindings = findings.filter(f => f.title === 'Sequential/numeric object identifier observed');
  assert.equal(idFindings.length, 1, 'same path template should dedupe to a single finding');
});

test('large numeric id (> 100000) does NOT emit idor finding', () => {
  const ctx = makeCtx([
    entry({
      url: 'https://api.example.test/items/9999999',
      method: 'GET',
      status: 200,
      resBody: '{}',
    }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  assert.ok(
    !findings.some(f => f.title === 'Sequential/numeric object identifier observed'),
    'large id must not trigger numeric id finding',
  );
});

// ---- Check 5: verbose error diagnostics -------------------------------------

test('400 response with stack field in JSON body emits low config finding', () => {
  const ctx = makeCtx([
    entry({
      url: 'https://api.example.test/api/action',
      method: 'POST',
      status: 400,
      resBody: JSON.stringify({
        error: 'Bad Request',
        stack: 'Error: validation failed\n    at validate (/app/src/validators.js:42:7)',
      }),
    }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  assert.ok(
    findings.some(f =>
      f.title === 'Error response exposes internal diagnostic fields' &&
      f.sev === 'low' &&
      f.owasp === 'API8:2023',
    ),
    'should emit diagnostic fields finding',
  );
  const f = findings.find(f => f.title === 'Error response exposes internal diagnostic fields');
  assert.equal(f.category, 'config');
  assert.equal(f.cwe, 'CWE-209');
  assert.equal(f.confidence, 'firm');
  assert.ok(f.evidence.includes('stack'), 'evidence should include the matched field name');
});

test('4xx response with generic error fields does NOT emit diagnostic finding', () => {
  const ctx = makeCtx([
    entry({
      url: 'https://api.example.test/api/action',
      method: 'POST',
      status: 422,
      resBody: JSON.stringify({ error: 'Unprocessable Entity', message: 'Invalid input' }),
    }),
  ]);
  const findings = analyzeRuntimeIntel(ctx);
  assert.ok(
    !findings.some(f => f.title === 'Error response exposes internal diagnostic fields'),
    'generic error response must not trigger diagnostic finding',
  );
});
