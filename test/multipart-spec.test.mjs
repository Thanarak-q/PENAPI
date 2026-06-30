import test from 'node:test';
import assert from 'node:assert/strict';

import specParser from '../lib/specParser.js';

const { parseSpec } = specParser;

test('OpenAPI 3 multipart/form-data body flags binary fields as files', () => {
  const spec = parseSpec({
    openapi: '3.0.0',
    info: { title: 'T', version: '1' },
    paths: {
      '/upload': {
        post: {
          requestBody: {
            required: true,
            content: {
              'multipart/form-data': {
                schema: {
                  type: 'object',
                  required: ['file'],
                  properties: {
                    file: { type: 'string', format: 'binary' },
                    note: { type: 'string' },
                  },
                },
              },
            },
          },
        },
      },
    },
  });
  const ep = spec.endpoints.find((e) => e.path === '/upload');
  assert.ok(ep.body.multipart, 'body marked multipart');
  const file = ep.body.fields.find((f) => f.name === 'file');
  const note = ep.body.fields.find((f) => f.name === 'note');
  assert.equal(file.isFile, true);
  assert.equal(file.required, true);
  assert.equal(note.isFile, false);
});

test('Swagger 2 in:formData file param synthesizes a multipart body', () => {
  const spec = parseSpec({
    swagger: '2.0',
    info: { title: 'T', version: '1' },
    paths: {
      '/upload': {
        post: {
          consumes: ['multipart/form-data'],
          parameters: [
            { name: 'file', in: 'formData', type: 'file', required: true },
            { name: 'caption', in: 'formData', type: 'string' },
          ],
        },
      },
    },
  });
  const ep = spec.endpoints.find((e) => e.path === '/upload');
  assert.ok(ep.body && ep.body.multipart);
  assert.equal(ep.body.contentType, 'multipart/form-data');
  assert.equal(ep.body.fields.find((f) => f.name === 'file').isFile, true);
  assert.equal(ep.body.fields.find((f) => f.name === 'caption').isFile, false);
});

test('non-multipart JSON body keeps its example and is not marked multipart', () => {
  const spec = parseSpec({
    openapi: '3.0.0',
    info: { title: 'T', version: '1' },
    paths: {
      '/x': {
        post: {
          requestBody: {
            content: { 'application/json': { schema: { type: 'object', properties: { a: { type: 'string' } } } } },
          },
        },
      },
    },
  });
  const ep = spec.endpoints.find((e) => e.path === '/x');
  assert.equal(ep.body.multipart, undefined);
  assert.deepEqual(ep.body.example, { a: 'string' });
});
