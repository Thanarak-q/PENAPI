import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeSpec } from '../public/js/static-analysis.js';

function makeSpec(overrides = {}) {
  return {
    title: 'Test API',
    version: '1.0.0',
    specVersion: '3.0.0',
    baseUrls: ['https://api.example.test'],
    securitySchemes: {
      bearerAuth: { type: 'http', scheme: 'bearer' },
    },
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
    operationId: overrides.operationId ?? 'health',
    summary: overrides.summary || 'Health check',
    description: overrides.description || 'Returns service status.',
    tags: overrides.tags || ['default'],
    deprecated: !!overrides.deprecated,
    params: {
      path: [],
      query: [],
      header: [],
      cookie: [],
      ...(overrides.params || {}),
    },
    body: overrides.body || null,
    security: overrides.security ?? [{ bearerAuth: [] }],
  };
}

function titles(report) {
  return report.findings.map((finding) => finding.title);
}

test('flags mutating unauthenticated operations and sensitive body fields', () => {
  const report = analyzeSpec(makeSpec({
    endpoints: [
      endpoint({
        method: 'POST',
        path: '/admin/users',
        operationId: 'createUser',
        security: [],
        body: {
          contentType: 'application/json',
          required: true,
          example: { email: 'user@example.test', role: 'admin', isAdmin: false },
        },
      }),
    ],
  }));

  assert.ok(titles(report).includes('Mutating operation has no required authentication'));
  assert.ok(titles(report).includes('Sensitive path has no required authentication'));
  assert.ok(titles(report).includes('Sensitive request body fields may allow mass assignment'));
  assert.equal(report.summary.severities.high, 1);
  assert.equal(report.summary.categories.security >= 2, true);
});

test('treats empty security requirement as optional authentication', () => {
  const report = analyzeSpec(makeSpec({
    endpoints: [
      endpoint({
        method: 'GET',
        path: '/me',
        operationId: 'getMe',
        security: [{}],
      }),
    ],
  }));

  assert.ok(titles(report).includes('Authentication is optional for this operation'));
  assert.equal(report.findings.some((finding) => finding.title === 'Operation has no security requirement'), false);
});

test('detects duplicate and missing operation IDs', () => {
  const report = analyzeSpec(makeSpec({
    endpoints: [
      endpoint({ method: 'GET', path: '/users', operationId: 'listUsers' }),
      endpoint({ method: 'POST', path: '/users', operationId: 'listUsers' }),
      endpoint({ method: 'GET', path: '/projects', operationId: '' }),
    ],
  }));

  assert.ok(titles(report).includes('Duplicate operationId'));
  assert.ok(titles(report).includes('Missing operationId'));
});

test('detects path token and path parameter mismatches', () => {
  const report = analyzeSpec(makeSpec({
    endpoints: [
      endpoint({
        method: 'GET',
        path: '/users/{id}/orders/{orderId}',
        operationId: 'getOrder',
        params: {
          path: [
            { name: 'id', required: false, description: 'User id' },
            { name: 'extraId', required: true, description: 'Unused id' },
          ],
        },
      }),
    ],
  }));

  assert.ok(titles(report).includes('Path token missing matching parameter'));
  assert.ok(titles(report).includes('Path parameter is not marked required'));
  assert.ok(titles(report).includes('Path parameter not present in path template'));
});

test('detects risky parameters and unknown security scheme references', () => {
  const report = analyzeSpec(makeSpec({
    endpoints: [
      endpoint({
        method: 'GET',
        path: '/files/{fileId}',
        operationId: 'downloadFile',
        security: [{ missingAuth: [] }],
        params: {
          path: [{ name: 'fileId', required: true, description: 'File id' }],
          query: [
            { name: 'redirectUrl', required: false, description: 'Redirect destination' },
            { name: 'debug', required: false, description: '' },
          ],
        },
      }),
    ],
  }));

  assert.ok(titles(report).includes('Security scheme is referenced but not defined'));
  assert.ok(titles(report).includes('Object identifier in path'));
  assert.ok(titles(report).includes('Risky query parameter'));
  assert.equal(report.summary.categories.injection >= 1, true);
});

test('analyzes request history without requiring active requests', () => {
  const report = analyzeSpec(
    makeSpec({
      endpoints: [
        endpoint({
          method: 'GET',
          path: '/users/{id}',
          operationId: 'getUser',
          security: [{ bearerAuth: [] }],
          params: {
            path: [{ name: 'id', required: true, description: 'User id' }],
          },
        }),
      ],
    }),
    [
      {
        method: 'GET',
        url: 'https://api.example.test/users/1',
        status: 200,
        request: { method: 'GET', url: 'https://api.example.test/users/1', headers: {} },
        response: { status: 200, headers: {}, body: '{"id":1,"token":"secret"}' },
      },
      {
        method: 'GET',
        url: 'https://api.example.test/internal/debug',
        status: 500,
        request: { method: 'GET', url: 'https://api.example.test/internal/debug', headers: {} },
        response: { status: 500, headers: {}, body: 'stack trace' },
      },
    ]
  );

  assert.ok(titles(report).includes('Authenticated endpoint succeeded without auth header in request log'));
  assert.ok(titles(report).includes('Sensitive data observed in response log'));
  assert.ok(titles(report).includes('Request log entry is not described by the loaded spec'));
  assert.ok(titles(report).includes('Server error observed in request log'));
  assert.equal(report.findings.some((finding) => finding.action?.includes('replay')), false);
});

test('flags a credential-like value carried in the URL', () => {
  const report = analyzeSpec(makeSpec({
    endpoints: [
      endpoint({
        method: 'GET',
        path: '/reset',
        params: { query: [{ name: 'token', required: true }] },
      }),
    ],
  }));
  assert.ok(titles(report).includes('Credential-like value carried in the URL'));
});

test('detects GraphQL, file-upload, and management surfaces', () => {
  const report = analyzeSpec(makeSpec({
    endpoints: [
      endpoint({ method: 'POST', path: '/graphql', operationId: 'gql' }),
      endpoint({
        method: 'POST',
        path: '/avatar/upload',
        operationId: 'upload',
        body: { contentType: 'multipart/form-data', required: true, example: {} },
      }),
      endpoint({ method: 'GET', path: '/actuator/env', operationId: 'env' }),
    ],
  }));
  const t = titles(report);
  assert.ok(t.includes('GraphQL endpoint detected'));
  assert.ok(t.includes('File-upload surface'));
  assert.ok(t.includes('Management or debug surface exposed'));
});

test('flags authentication carried over plaintext HTTP', () => {
  const report = analyzeSpec(makeSpec({
    baseUrls: ['http://api.example.test'],
    endpoints: [endpoint({})],
  }));
  assert.ok(titles(report).includes('Credentials may be sent over plaintext HTTP'));
});

test('flags an API key transmitted in the query string', () => {
  const report = analyzeSpec(makeSpec({
    securitySchemes: { apiKeyAuth: { type: 'apiKey', in: 'query', name: 'api_key' } },
    endpoints: [endpoint({ security: [{ apiKeyAuth: [] }] })],
  }));
  assert.ok(titles(report).includes('API key transmitted in the query string'));
});

test('flags a discouraged OAuth2 grant', () => {
  const report = analyzeSpec(makeSpec({
    securitySchemes: { oauth: { type: 'oauth2', flows: { implicit: { authorizationUrl: 'x' } } } },
    endpoints: [endpoint({ security: [{ oauth: [] }] })],
  }));
  assert.ok(titles(report).includes('OAuth2 uses a discouraged grant (implicit/password)'));
});
