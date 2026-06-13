import test from 'node:test';
import assert from 'node:assert/strict';

import specParser from '../lib/specParser.js';

const { parseSpec, exampleFromSchema, resolveRef } = specParser;

test('resolveRef walks a local JSON pointer and decodes ~1/~0', () => {
  const root = { components: { schemas: { 'A/B': { x: 1 } } } };
  assert.deepEqual(resolveRef(root, '#/components/schemas/A~1B'), { x: 1 });
  assert.equal(resolveRef(root, '#/missing/path'), undefined);
  assert.equal(resolveRef(root, 'not-a-ref'), undefined);
});

test('exampleFromSchema synthesizes by type and format', () => {
  assert.equal(exampleFromSchema({}, { type: 'string', format: 'uuid' }, 0, new Set()), '00000000-0000-0000-0000-000000000000');
  assert.equal(exampleFromSchema({}, { type: 'integer' }, 0, new Set()), 0);
  assert.equal(exampleFromSchema({}, { type: 'boolean' }, 0, new Set()), false);
  assert.deepEqual(exampleFromSchema({}, { type: 'object', properties: { a: { type: 'string' } } }, 0, new Set()), { a: 'string' });
  assert.deepEqual(exampleFromSchema({}, { type: 'array', items: { type: 'integer' } }, 0, new Set()), [0]);
});

test('exampleFromSchema prefers example > default > enum', () => {
  assert.equal(exampleFromSchema({}, { type: 'string', example: 'X', default: 'Y', enum: ['Z'] }, 0, new Set()), 'X');
  assert.equal(exampleFromSchema({}, { type: 'string', default: 'Y', enum: ['Z'] }, 0, new Set()), 'Y');
  assert.equal(exampleFromSchema({}, { type: 'string', enum: ['Z'] }, 0, new Set()), 'Z');
});

test('exampleFromSchema resolves $ref and survives a cycle', () => {
  const root = { components: { schemas: { Node: { type: 'object', properties: { next: { $ref: '#/components/schemas/Node' }, val: { type: 'string' } } } } } };
  const out = exampleFromSchema(root, { $ref: '#/components/schemas/Node' }, 0, new Set());
  assert.equal(out.val, 'string');
  assert.deepEqual(out.next, {}); // cycle short-circuits to {}
});

test('exampleFromSchema merges allOf', () => {
  const schema = { allOf: [{ type: 'object', properties: { a: { type: 'string' } } }, { type: 'object', properties: { b: { type: 'integer' } } }] };
  assert.deepEqual(exampleFromSchema({}, schema, 0, new Set()), { a: 'string', b: 0 });
});

test('parseSpec normalizes an OpenAPI 3 document', () => {
  const doc = {
    openapi: '3.0.0',
    info: { title: 'Demo', version: '1.2.3' },
    servers: [{ url: 'https://{host}/v1', variables: { host: { default: 'api.test' } } }],
    components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } } },
    paths: {
      '/users/{id}': {
        get: {
          operationId: 'getUser',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
          security: [{ bearerAuth: [] }],
        },
        post: {
          operationId: 'createUser',
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' } } } } } },
        },
      },
    },
  };
  const spec = parseSpec(doc);
  assert.equal(spec.title, 'Demo');
  assert.equal(spec.specVersion, '3.0.0');
  assert.deepEqual(spec.baseUrls, ['https://api.test/v1']);
  assert.equal(spec.stats.endpoints, 2);
  const get = spec.endpoints.find((e) => e.id === 'GET /users/{id}');
  assert.equal(get.params.path[0].name, 'id');
  assert.deepEqual(get.security, [{ bearerAuth: [] }]);
  const post = spec.endpoints.find((e) => e.method === 'POST');
  assert.deepEqual(post.body.example, { name: 'string' });
});

test('parseSpec handles a Swagger 2.0 document with a body parameter', () => {
  const doc = {
    swagger: '2.0',
    info: { title: 'V2', version: '1' },
    host: 'api.test',
    basePath: '/v2',
    schemes: ['https'],
    securityDefinitions: { apiKey: { type: 'apiKey', in: 'header', name: 'X-Key' } },
    paths: {
      '/things': {
        post: {
          operationId: 'addThing',
          parameters: [{ name: 'body', in: 'body', required: true, schema: { type: 'object', properties: { n: { type: 'integer' } } } }],
        },
      },
    },
  };
  const spec = parseSpec(doc);
  assert.deepEqual(spec.baseUrls, ['https://api.test/v2']);
  assert.equal(spec.securitySchemes.apiKey.in, 'header');
  assert.deepEqual(spec.endpoints[0].body.example, { n: 0 });
});

test('parseSpec throws on an unrecognized document', () => {
  assert.throws(() => parseSpec({ foo: 'bar' }));
});

test('parseSpec surfaces TRACE operations (XST surface)', () => {
  const doc = { openapi: '3.0.0', paths: { '/x': { trace: { operationId: 'trace' } } } };
  const spec = parseSpec(doc);
  assert.ok(spec.endpoints.some((e) => e.method === 'TRACE'));
});
