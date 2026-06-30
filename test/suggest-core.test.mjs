import test from 'node:test';
import assert from 'node:assert/strict';

import { suggestSets } from '../public/js/analyzers/suggest.js';

const keys = (s) => s.map((x) => x.key);

test('suggests redirect/SSRF sets for a url-style query parameter', () => {
  const k = keys(suggestSets({ url: 'https://h/api/fetch?next=https://x' }));
  assert.ok(k.includes('open-redirect'));
  assert.ok(k.includes('ssrf'));
});

test('suggests traversal/LFI for a file/path parameter', () => {
  const k = keys(suggestSets({ url: 'https://h/download?file=a.pdf' }));
  assert.ok(k.includes('path-traversal'));
  assert.ok(k.includes('lfi'));
});

test('suggests SQLi/XSS for a free-text search parameter', () => {
  const k = keys(suggestSets({ url: 'https://h/items?q=test' }));
  assert.ok(k.includes('sqli'));
  assert.ok(k.includes('xss'));
});

test('suggests GraphQL sets for a graphql path', () => {
  const k = keys(suggestSets({ url: 'https://h/graphql' }));
  assert.ok(k.includes('graphql'));
  assert.ok(k.includes('graphql-injection'));
});

test('suggests auth sets for a login endpoint', () => {
  const k = keys(suggestSets({ url: 'https://h/api/login', method: 'POST' }));
  assert.ok(k.includes('auth-bypass'));
  assert.ok(k.includes('jwt-attacks'));
});

test('suggests mass-assignment and type-juggling for a mutating JSON object body', () => {
  const k = keys(suggestSets({ url: 'https://h/users', method: 'POST', contentType: 'application/json', body: '{"name":"x","role":"user"}' }));
  assert.ok(k.includes('mass-assignment'));
  assert.ok(k.includes('type-juggling'));
});

test('does not suggest mass-assignment for a GET (non-mutating) request', () => {
  const k = keys(suggestSets({ url: 'https://h/users', method: 'GET', body: '' }));
  assert.ok(!k.includes('mass-assignment'));
});

test('suggests XXE for an XML body', () => {
  const k = keys(suggestSets({ url: 'https://h/ingest', method: 'POST', contentType: 'application/xml', body: '<?xml version="1.0"?><a/>' }));
  assert.ok(k.includes('xxe'));
});

test('suggests CSV injection for an export endpoint', () => {
  const k = keys(suggestSets({ url: 'https://h/reports/export?name=x' }));
  assert.ok(k.includes('csv-injection'));
});

test('suggests parameter pollution when multiple query params are present', () => {
  const k = keys(suggestSets({ url: 'https://h/x?a=1&b=2' }));
  assert.ok(k.includes('param-pollution'));
});

test('falls back to general fuzzing when nothing specific matches', () => {
  const s = suggestSets({ url: 'https://h/healthz' });
  assert.ok(s.length >= 1);
  assert.ok(keys(s).includes('format-fuzz'));
});

test('respects the result limit and returns {key, why} objects', () => {
  const s = suggestSets({ url: 'https://h/api/login?next=/&file=a&q=b', method: 'POST', contentType: 'application/json', body: '{"a":1}' }, 4);
  assert.ok(s.length <= 4);
  for (const item of s) {
    assert.ok(typeof item.key === 'string' && item.key.length > 0);
    assert.ok(typeof item.why === 'string' && item.why.length > 0);
  }
});
