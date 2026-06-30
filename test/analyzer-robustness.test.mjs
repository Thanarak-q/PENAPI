import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeSpec } from '../public/js/static-analysis.js';
import { runExtraAnalyzers, ANALYZERS } from '../public/js/analyzers/index.js';

const SEVERITIES = new Set(['high', 'medium', 'low', 'info']);
const CATEGORIES = new Set(['security', 'idor', 'injection', 'data', 'config', 'resource', 'inventory', 'quality', 'logs']);

function assertWellFormed(findings) {
  for (const f of findings) {
    assert.ok(SEVERITIES.has(f.sev), `bad sev: ${f.sev} (${f.title})`);
    assert.ok(CATEGORIES.has(f.category), `bad category: ${f.category} (${f.title})`);
    assert.ok(typeof f.title === 'string' && f.title.length > 0, 'empty title');
    assert.ok(['firm', 'tentative'].includes(f.confidence), `bad confidence: ${f.confidence}`);
    assert.equal(typeof f.owasp, 'string');
    assert.equal(typeof f.cwe, 'string');
    assert.ok(['spec', 'history'].includes(f.source), `bad source: ${f.source}`);
  }
}

test('analyzeSpec tolerates null / empty / partial specs without throwing', () => {
  for (const input of [null, undefined, {}, { endpoints: null }, { endpoints: [{}] }, { baseUrls: null, securitySchemes: null }]) {
    const report = analyzeSpec(input, null);
    assert.ok(Array.isArray(report.findings));
    assert.ok(report.summary);
    assertWellFormed(report.findings);
  }
});

test('analyzeSpec tolerates malformed history entries', () => {
  const history = [
    null,
    {},
    { request: null, response: null },
    { request: { method: 'POST' }, response: { status: 'oops', headers: null, body: null } },
    { request: { url: 'not a url', headers: { cookie: 'a=b' } }, response: { status: 500, headers: { 'set-cookie': '\n\n' }, body: '{bad json' } },
  ];
  const report = analyzeSpec({ endpoints: [], baseUrls: ['https://h'], securitySchemes: {} }, history);
  assert.ok(Array.isArray(report.findings));
  assertWellFormed(report.findings);
});

test('every registered analyzer returns an array for empty context', () => {
  const ctx = { spec: {}, endpoints: [], securitySchemes: {}, history: [], records: [] };
  for (const { fn } of ANALYZERS) {
    const out = fn(ctx);
    assert.ok(Array.isArray(out), `${fn.name} did not return an array`);
  }
});

test('runExtraAnalyzers returns well-formed specs on a rich vulnerable input', () => {
  const endpoints = [
    { id: 'GET /v1/users/{id}', method: 'GET', path: '/v1/users/{id}', operationId: 'g', summary: '', description: '', tags: ['u'], deprecated: false, params: { path: [{ name: 'id', in: 'path', required: true }], query: [], header: [], cookie: [] }, body: null, security: [] },
    { id: 'POST /v2/checkout', method: 'POST', path: '/v2/checkout', operationId: 'checkout', summary: '', description: '', tags: ['s'], deprecated: false, params: { path: [], query: [], header: [], cookie: [] }, body: { contentType: 'application/json', example: { quantity: 1 } }, security: [{ basicAuth: [] }] },
  ];
  const history = [
    { request: { method: 'POST', url: 'http://staging.h/v2/checkout', headers: { cookie: 'sid=1', 'content-type': 'application/x-www-form-urlencoded' }, body: 'amt=1' }, response: { status: 200, headers: { 'access-control-allow-origin': '*' }, body: '{"email":"a@b.com"}' } },
  ];
  const specs = runExtraAnalyzers({ spec: { baseUrls: ['http://staging.h'] }, endpoints, securitySchemes: { basicAuth: { type: 'http', scheme: 'basic' } }, history });
  assert.ok(specs.length > 0);
  // runExtraAnalyzers returns un-normalized specs (no confidence default yet); check the essentials.
  for (const s of specs) {
    assert.ok(SEVERITIES.has(s.sev));
    assert.ok(CATEGORIES.has(s.category));
    assert.ok(typeof s.title === 'string' && s.title.length > 0);
  }
});

test('a deeply vulnerable spec yields only well-formed, classified findings', () => {
  const report = analyzeSpec(
    {
      baseUrls: ['http://staging.h/v1'],
      securitySchemes: { basicAuth: { type: 'http', scheme: 'basic' } },
      endpoints: [
        { id: 'POST /v1/users/bulk', method: 'POST', path: '/v1/users/bulk', operationId: 'b', tags: ['u'], deprecated: false, params: { path: [], query: [], header: [], cookie: [] }, body: { contentType: 'application/json', example: [{ x: 1 }] }, security: [] },
      ],
    },
    [{ request: { method: 'POST', url: 'http://staging.h/v1/users/bulk', headers: {} }, response: { status: 500, headers: {}, body: 'Traceback (most recent call last)' } }]
  );
  assert.ok(report.findings.length > 5);
  assertWellFormed(report.findings);
});
