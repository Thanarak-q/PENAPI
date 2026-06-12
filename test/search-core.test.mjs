import test from 'node:test';
import assert from 'node:assert/strict';

import { entryFields, buildMatcher, searchHistory } from '../public/js/search-core.js';

const history = [
  {
    method: 'GET', url: 'https://api.test/users/1',
    request: { headers: { Authorization: 'Bearer abc' }, body: null },
    response: { headers: { 'content-type': 'application/json' }, body: '{"email":"ada@x.test"}' },
  },
  {
    method: 'POST', url: 'https://api.test/login',
    request: { headers: {}, body: '{"user":"admin"}' },
    response: { headers: {}, body: 'Internal Server Error: NullPointer' },
  },
];

test('entryFields exposes method, url, headers, and bodies', () => {
  const fields = entryFields(history[0]).map((f) => f.field);
  assert.deepEqual(fields, ['method', 'url', 'request headers', 'request body', 'response headers', 'response body']);
});

test('substring search matches a response body and tags the field', () => {
  const r = searchHistory(history, 'ada@x.test');
  assert.equal(r.length, 1);
  assert.equal(r[0].entry.url, 'https://api.test/users/1');
  assert.ok(r[0].matchedFields.includes('response body'));
});

test('search is case-insensitive by default', () => {
  assert.equal(searchHistory(history, 'BEARER').length, 1);
  assert.equal(searchHistory(history, 'BEARER', { caseSensitive: true }).length, 0);
});

test('regex search matches across entries', () => {
  const r = searchHistory(history, 'Null\\w+', { regex: true });
  assert.equal(r.length, 1);
  assert.ok(r[0].matchedFields.includes('response body'));
});

test('empty query and invalid regex return no results', () => {
  assert.deepEqual(searchHistory(history, ''), []);
  assert.equal(buildMatcher('(', { regex: true }), null);
});

test('a query hitting multiple entries returns all of them', () => {
  const r = searchHistory(history, 'api.test');
  assert.equal(r.length, 2);
});
